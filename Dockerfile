# syntax=docker/dockerfile:1
# Builder: golang 1.27.4 (bookworm), pinned by digest. Update the tag and digest together.
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w -X github.com/samiali38183/kevgate-admit/internal/app.Version=${VERSION}" \
    -o /out/kevgate-admit ./cmd/kevgate-admit

# Runtime: distroless static (Debian 13), nonroot variant, pinned by digest.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/kevgate-admit /kevgate-admit
USER 65532:65532
EXPOSE 8443 8080
ENTRYPOINT ["/kevgate-admit"]
CMD ["serve"]
