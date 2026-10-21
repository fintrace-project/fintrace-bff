# Unlike the Kotlin services, the binary is built here: a Go build needs no warm daemon, and
# compiling in the image keeps run-local.sh and the release job free of a separate build step.
FROM golang:1.27.2 AS build
WORKDIR /src

COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
# Static, so it runs on distroless with no libc
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fintrace-bff ./cmd/fintrace-bff

# No shell and no package manager; ships CA certificates for the realm and tzdata for TZ
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fintrace-bff /fintrace-bff

EXPOSE 8080
# Exec form, so SIGTERM from `docker stop` reaches the binary and shuts it down gracefully
ENTRYPOINT ["/fintrace-bff"]
