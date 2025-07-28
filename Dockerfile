### Stage 1: build spectre binaries
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential cmake git libboost-all-dev libssl-dev pkg-config golang-go \
        wget curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src
RUN mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) && \
    mkdir -p plugins_flat && find . -name '*.so' -exec cp {} plugins_flat/ \; && \
    cd ../cli && go build -o ../build/cli/spectre && cd ../build

FROM ubuntu:22.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        libstdc++6 libssl3 libboost-system1.74.0 libboost-thread1.74.0 libboost-chrono1.74.0 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/spectre

COPY --from=builder /src/build/spectre-d/spectre-d ./spectre-d
COPY --from=builder /src/build/cli/spectre ./spectre-cli
COPY --from=builder /src/build/plugins_flat/*.so ./plugins/
COPY web ./web

RUN groupadd -r spectre && useradd -r -g spectre spectre && chown -R spectre:spectre /opt/spectre
USER spectre

EXPOSE 8888/udp 8889

ENTRYPOINT ["/opt/spectre/spectre-d","/opt/spectre/plugins"] 