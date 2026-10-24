# Hardened Air-Gapped Container for offtest
FROM python:3.12-slim

# Create dedicated non-root unprivileged user and directories
RUN groupadd -g 10001 offtest && \
    useradd -u 10001 -g offtest -m -s /bin/sh offtest && \
    mkdir -p /app /repo /out && \
    chown -R offtest:offtest /app /out

WORKDIR /app

# Copy package sources and install offline dependencies
COPY --chown=offtest:offtest . /app
RUN pip install --no-cache-dir -e /app

# Drop all privileges and run as non-root user
USER 10001:10001

ENTRYPOINT ["offtest"]
CMD ["--help"]
