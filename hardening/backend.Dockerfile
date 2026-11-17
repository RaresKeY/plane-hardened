FROM sha256:78976a69c067520ef8be34cde307ef9f6fea6dcefa50edb57039773d241ca0db AS dependencies
WORKDIR /build
COPY wheels /wheels
COPY production-py312.lock runtime_image.py ./
RUN ["python3", "/build/runtime_image.py", "install", "--image-build"]

FROM sha256:78976a69c067520ef8be34cde307ef9f6fea6dcefa50edb57039773d241ca0db
RUN --mount=type=bind,source=zlib1g.deb,target=/tmp/zlib1g.deb,ro ["dpkg", "-i", "/tmp/zlib1g.deb"]
LABEL io.rareskey.retention="ephemeral" io.rareskey.project="plane-hardened" io.rareskey.purpose="backend-qualification"
ENV PATH="/opt/venv/bin:/usr/local/bin:/usr/bin:/bin" \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=plane.settings.hardened \
    HOME=/tmp/plane XDG_CACHE_HOME=/tmp/plane/cache PLANE_LOG_DIR=/tmp/plane/logs \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/etc/ssl/certs/ca-certificates.crt
COPY --from=dependencies /opt/venv /opt/venv
COPY trust_policy.py policy.json runtime_image.py http_framing_patch.py /opt/plane-hardening/
RUN ["/usr/local/bin/python3", "/opt/plane-hardening/runtime_image.py", "harden", "--image-build"]
WORKDIR /code
COPY api /code
COPY LICENSE.txt /usr/share/doc/plane/LICENSE.txt
COPY backend_entrypoint.py /opt/plane-hardening/backend_entrypoint.py
COPY runtime_health.py /opt/plane-hardening/runtime_health.py
USER 1000:1000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/opt/venv/bin/python", "/opt/plane-hardening/backend_entrypoint.py", "health"]
ENTRYPOINT ["/opt/venv/bin/python", "/opt/plane-hardening/backend_entrypoint.py"]
CMD ["api"]
