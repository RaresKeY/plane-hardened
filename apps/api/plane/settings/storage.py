# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import os
import uuid

# Third party imports
import boto3
from botocore.exceptions import ClientError
from urllib.parse import quote, urlsplit

# Module imports
from plane.utils.exception_logger import log_exception
from storages.backends.s3boto3 import S3Boto3Storage


def configured_s3_endpoint(value):
    try:
        if not isinstance(value, str) or len(value) > 2048 or any(ord(char) <= 32 for char in value):
            raise ValueError
        parts = urlsplit(value)
        if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.query or parts.fragment or parts.path not in ("", "/")
                or parts.port is not None and not 1 <= parts.port <= 65535):
            raise ValueError
    except ValueError:
        raise ValueError("Configure an HTTP(S) S3 endpoint origin without credentials, paths or query data") from None
    return value


class S3Storage(S3Boto3Storage):
    def url(self, name, parameters=None, expire=None, http_method=None):
        return name

    """S3 storage class to generate presigned URLs for S3 objects"""

    def __init__(self, request=None, is_server=False):
        # Get the AWS credentials and bucket name from the environment
        self.aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
        # Use the AWS_SECRET_ACCESS_KEY environment variable for the secret key
        self.aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
        # Use the AWS_S3_BUCKET_NAME environment variable for the bucket name
        self.aws_storage_bucket_name = os.environ.get("AWS_S3_BUCKET_NAME")
        # Use the AWS_REGION environment variable for the region
        self.aws_region = os.environ.get("AWS_REGION")
        # Use the AWS_S3_ENDPOINT_URL environment variable for the endpoint URL
        self.aws_s3_endpoint_url = os.environ.get("AWS_S3_ENDPOINT_URL") or os.environ.get("MINIO_ENDPOINT_URL")
        # Use the SIGNED_URL_EXPIRATION environment variable for the expiration time (default: 3600 seconds)
        self.signed_url_expiration = int(os.environ.get("SIGNED_URL_EXPIRATION", "3600"))

        if os.environ.get("USE_MINIO") == "1":
            # A request Host/scheme is not authority to select a credentialed
            # storage endpoint. Public signatures use the configured gateway;
            # server/background work uses the operator's internal endpoint.
            endpoint = (self.aws_s3_endpoint_url if is_server or request is None else
                        os.environ.get("PUBLIC_S3_ENDPOINT_URL") or os.environ.get("WEB_URL"))
            # Create an S3 client for MinIO
            self.s3_client = boto3.client(
                "s3",
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                region_name=self.aws_region,
                endpoint_url=configured_s3_endpoint(endpoint),
                config=boto3.session.Config(signature_version="s3v4"),
            )
        else:
            # Create an S3 client
            self.s3_client = boto3.client(
                "s3",
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                region_name=self.aws_region,
                endpoint_url=configured_s3_endpoint(self.aws_s3_endpoint_url) if self.aws_s3_endpoint_url else None,
                config=boto3.session.Config(signature_version="s3v4"),
            )

    def generate_presigned_post(self, object_name, file_type, file_size, expiration=None):
        """Generate a presigned URL to upload an S3 object"""
        if expiration is None:
            expiration = self.signed_url_expiration
        fields = {"Content-Type": file_type}

        conditions = [
            {"bucket": self.aws_storage_bucket_name},
            ["content-length-range", 1, file_size],
            {"Content-Type": file_type},
        ]

        # Add condition for the object name (key)
        if object_name.startswith("${filename}"):
            conditions.append(["starts-with", "$key", object_name[: -len("${filename}")]])
        else:
            fields["key"] = object_name
            conditions.append({"key": object_name})

        # Generate the presigned POST URL
        try:
            # Generate a presigned URL for the S3 object
            response = self.s3_client.generate_presigned_post(
                Bucket=self.aws_storage_bucket_name,
                Key=object_name,
                Fields=fields,
                Conditions=conditions,
                ExpiresIn=expiration,
            )
        # Handle errors
        except ClientError as e:
            log_exception(e)
            return None

        return response

    def _get_content_disposition(self, disposition, filename=None):
        """Helper method to generate Content-Disposition header value"""
        if filename is None:
            filename = uuid.uuid4().hex

        if filename:
            # Encode the filename to handle special characters
            encoded_filename = quote(filename)
            return f"{disposition}; filename*=UTF-8''{encoded_filename}"
        return disposition

    def generate_presigned_url(
        self,
        object_name,
        expiration=None,
        http_method="GET",
        disposition="inline",
        filename=None,
    ):
        """Generate a presigned URL to share an S3 object"""
        if expiration is None:
            expiration = self.signed_url_expiration
        content_disposition = self._get_content_disposition(disposition, filename)
        try:
            response = self.s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.aws_storage_bucket_name,
                    "Key": str(object_name),
                    "ResponseContentDisposition": content_disposition,
                },
                ExpiresIn=expiration,
                HttpMethod=http_method,
            )
        except ClientError as e:
            log_exception(e)
            return None

        # The response contains the presigned URL
        return response

    def get_object_metadata(self, object_name):
        """Get the metadata for an S3 object"""
        try:
            response = self.s3_client.head_object(Bucket=self.aws_storage_bucket_name, Key=object_name)
        except ClientError as e:
            log_exception(e)
            return None

        return {
            "ContentType": response.get("ContentType"),
            "ContentLength": response.get("ContentLength"),
            "LastModified": (response.get("LastModified").isoformat() if response.get("LastModified") else None),
            "ETag": response.get("ETag"),
            "Metadata": response.get("Metadata", {}),
        }

    def copy_object(self, object_name, new_object_name):
        """Copy an S3 object to a new location"""
        try:
            response = self.s3_client.copy_object(
                Bucket=self.aws_storage_bucket_name,
                CopySource={"Bucket": self.aws_storage_bucket_name, "Key": object_name},
                Key=new_object_name,
            )
        except ClientError as e:
            log_exception(e)
            return None

        return response

    def upload_file(
        self,
        file_obj,
        object_name: str,
        content_type: str = None,
        extra_args: dict = {},
    ) -> bool:
        """Upload a file directly to S3"""
        try:
            if content_type:
                extra_args["ContentType"] = content_type

            self.s3_client.upload_fileobj(
                file_obj,
                self.aws_storage_bucket_name,
                object_name,
                ExtraArgs=extra_args,
            )
            return True
        except ClientError as e:
            log_exception(e)
            return False

    def delete_files(self, object_names):
        """Delete an S3 object"""
        try:
            self.s3_client.delete_objects(
                Bucket=self.aws_storage_bucket_name,
                Delete={"Objects": [{"Key": object_name} for object_name in object_names]},
            )
            return True
        except ClientError as e:
            log_exception(e)
            return False
