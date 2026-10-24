# Hardened Air-Gapped Multi-Stage Container for offtest
# Stage 1: Build environment
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS builder

WORKDIR /build
COPY . /build
RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir -w /build/wheels /build

# Stage 2: Minimal hardened runtime
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS runtime

# Create dedicated non-root unprivileged user and sandbox mount points
RUN groupadd -g 10001 offtest && \
    useradd -u 10001 -g offtest -m -s /bin/sh -d /tmp offtest && \
    mkdir -p /repo /out && \
    chown -R offtest:offtest /repo /out

WORKDIR /tmp

# Copy wheels from builder and install hermetically without build tools
COPY --from=builder /build/wheels /tmp/wheels
RUN pip install --no-cache-dir --no-index --find-links=/tmp/wheels offtest && \
    rm -rf /tmp/wheels

# Set offline environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp

# Drop all privileges and run as non-root user
USER 10001:10001

ENTRYPOINT ["offtest"]
CMD ["--help"]
