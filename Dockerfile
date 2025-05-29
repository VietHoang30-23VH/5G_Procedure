FROM debian:bookworm-slim AS builder
 
RUN apt-get update && \
    apt-get install -y build-essential flex bison libpcap-dev libssl-dev libtirpc-dev wget
 
WORKDIR /opt
 
RUN wget https://github.com/openargus/argus/archive/refs/tags/v5.0.2.tar.gz && \
    tar -xvzf v5.0.2.tar.gz && \
    cd argus-5.0.2 && \
    CFLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2" ./configure && make -j$(nproc) && make install
 
FROM debian:bookworm-slim
 
RUN apt-get update && \
    apt-get install -y libpcap0.8 libssl3 libtirpc3 && \
    rm -rf /var/lib/apt/lists/*
 
COPY --from=builder /usr/local/sbin/argus /usr/local/sbin/argus
COPY --from=builder /usr/local/bin/argus-* /usr/local/bin/
COPY --from=builder /usr/local/bin/argusbug /usr/local/bin/
 
EXPOSE 561
 
CMD ["/usr/local/sbin/argus", "-i", "any", "-P", "561"]
 
