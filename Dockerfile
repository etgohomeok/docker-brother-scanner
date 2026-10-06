# Dependencies are fetched on the build machine for the target architecture, so
# multi-arch builds need no emulation.
FROM --platform=$BUILDPLATFORM python:3.14-alpine AS deps
ARG TARGETARCH
RUN apk add --no-cache tzdata \
    && case "$TARGETARCH" in \
         amd64) arch=x86_64 ;; \
         arm64) arch=aarch64 ;; \
         *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && pip install --no-cache-dir --target /deps --only-binary=:all: \
         --platform "musllinux_1_2_$arch" --python-version 3.14 --implementation cp \
         pillow==12.3.0

FROM python:3.14-alpine

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/deps
COPY --from=deps /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=deps /deps /deps
COPY brother_scanner.py /app/brother_scanner.py

HEALTHCHECK --interval=60s --timeout=10s --start-period=60s \
    CMD ["python3", "/app/brother_scanner.py", "--healthcheck"]

ENTRYPOINT ["python3", "/app/brother_scanner.py"]
