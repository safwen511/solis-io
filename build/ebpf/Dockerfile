FROM golang:1.25.5-bookworm

# This is a controlled convenience environment, not a bit-for-bit
# reproducible release builder. Before release generation, pin the base image
# by a verified digest and lock verified Clang/LLVM/libbpf package versions.

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        libbpf-dev \
        llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Mount the repository at /src and run as the host UID/GID so the generated
# object is not root-owned. README.md contains the complete command.
CMD ["go", "generate", "./internal/ebpf"]
