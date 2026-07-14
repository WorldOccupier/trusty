FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /trusty ./cmd/trusty/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates git
COPY --from=builder /trusty /usr/local/bin/trusty
ENTRYPOINT ["trusty"]
CMD ["--help"]
