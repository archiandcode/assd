FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/url-generator .

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app

WORKDIR /app

COPY --from=builder /out/url-generator /app/url-generator

RUN mkdir -p /app/storage/files /app/storage/meta && chown -R app:app /app

USER app

ENV PORT=8010
EXPOSE 8010

VOLUME ["/app/storage"]

ENTRYPOINT ["/app/url-generator"]
