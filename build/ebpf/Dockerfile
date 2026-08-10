FROM golang:1.25.5-bookworm

# This is a controlled convenience environment, not a bit-for-bit
# reproducible release builder. Before release generation, pin the base image
# by a verified digest and lock verified Clang/LLVM package versions.

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Mount the repository at /src and run as the host UID/GID so the generated
# object is not root-owned. README.md contains the complete command.
CMD ["go", "generate", "./internal/ebpf"]
