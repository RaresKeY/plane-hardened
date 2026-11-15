"""Explicit operator-owned SSH routing; never commit a workstation profile."""

from dataclasses import dataclass
import os
from pathlib import PurePosixPath
import re


def absolute_directory(value):
    # Build staging also embeds this value in remote shell commands and mounts.
    if (
        not re.fullmatch(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", value)
        or any(part in (".", "..") for part in value.split("/"))
    ):
        raise ValueError("Use an absolute directory without traversal, whitespace or shell/mount syntax")
    return PurePosixPath(value)


@dataclass(frozen=True)
class OperatorConfig:
    host: str
    root: str

    @property
    def ssh(self):
        return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", self.host]

    def dependency_directory(self, value, environ=None):
        environ = os.environ if environ is None else environ
        approved = environ.get("PLANE_QUALIFICATION_INTAKE_ROOT", "")
        if not approved:
            raise ValueError("Set PLANE_QUALIFICATION_INTAKE_ROOT to the reviewed remote intake parent")
        parent = absolute_directory(approved)
        candidate = absolute_directory(value)
        if candidate.parent != parent or not candidate.name.startswith("plane-js-"):
            raise ValueError("Dependencies must be a plane-js-* directory directly under the reviewed intake root")
        return str(candidate)


def load_operator_config(environ=None):
    environ = os.environ if environ is None else environ
    host = environ.get("PLANE_QUALIFICATION_HOST", "")
    root = environ.get("PLANE_QUALIFICATION_ROOT", "")
    if not host or not root:
        raise ValueError("Set PLANE_QUALIFICATION_HOST and PLANE_QUALIFICATION_ROOT explicitly")
    # Only an SSH alias/hostname, optionally prefixed by a username, never flags.
    component = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
    if not re.fullmatch(rf"(?:{component}@)?{component}", host):
        raise ValueError("Use an SSH alias or user@hostname without options or shell syntax")
    return OperatorConfig(host, str(absolute_directory(root)))


def operator_config(parser):
    try:
        return load_operator_config()
    except ValueError as error:
        parser.error(str(error))
