
# builder image
FROM registry.access.redhat.com/ubi9/go-toolset:latest AS builder

ENV TINYGO_VERSION=0.31.2

USER root
WORKDIR /tmp/src
# Copying in source code
COPY main.go .
COPY go.mod .
COPY go.sum .
# Change file ownership to the assemble user. Builder image must support chown command.
RUN chown -R 1001:0 /tmp/src && \
  curl -L -O --output-dir /tmp https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo${TINYGO_VERSION}.linux-amd64.tar.gz && \
  tar -xf /tmp/tinygo${TINYGO_VERSION}.linux-amd64.tar.gz -C /tmp && \
  export PATH=$PATH:/tmp/tinygo/bin && \
  tinygo build -o main.wasm -scheduler=none -target=wasi ./main.go


USER 1001
# Assemble script sourced from builder image based on user input or image metadata.
# If this file does not exist in the image, the build will fail.
RUN /usr/libexec/s2i/assemble
