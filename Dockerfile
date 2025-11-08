FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o wg-manager .

FROM alpine:latest

# Install networking tools
RUN apk add --no-cache \
    ca-certificates \
    wireguard-tools \
    iptables \
    iproute2 \
    iputils \
    net-tools \
    tcpdump \
    curl \
    wget \
    docker-cli \
    bind-tools \
    busybox-extras \
    bash \
    vim \
    && rm -rf /var/cache/apk/*


WORKDIR /app
COPY --from=builder /app/wg-manager .

EXPOSE 8080

CMD ["./wg-manager"]