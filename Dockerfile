FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS builder

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
