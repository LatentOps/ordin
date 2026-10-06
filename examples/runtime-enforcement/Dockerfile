FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /readonly /workspace \
    && printf 'non-secret runtime fixture\n' > /readonly/input.txt \
    && chown -R 1000:1000 /readonly /workspace \
    && chmod 0777 /readonly && chmod 0666 /readonly/input.txt
WORKDIR /workspace
CMD ["/usr/bin/sleep", "infinity"]
