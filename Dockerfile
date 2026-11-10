FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS builder

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
