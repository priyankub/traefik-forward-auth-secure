FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

ARG TARGETOS
ARG TARGETARCH

# Setup
RUN mkdir -p /go/src/github.com/priyankub/traefik-forward-auth-secure
WORKDIR /go/src/github.com/priyankub/traefik-forward-auth-secure

# Add libraries
RUN apk add --no-cache git

# Copy & build
ADD . /go/src/github.com/priyankub/traefik-forward-auth-secure/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GO111MODULE=on go build -a -installsuffix nocgo -o /traefik-forward-auth github.com/priyankub/traefik-forward-auth-secure/cmd

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-forward-auth ./
ENTRYPOINT ["./traefik-forward-auth"]
