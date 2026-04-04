FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETARCH

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o pong-backend-go ./cmd/server

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/pong-backend-go .
COPY --from=builder /build/migrations/ ./migrations/
COPY --from=builder /build/templates/ ./templates/

EXPOSE 8080

ENTRYPOINT ["./pong-backend-go"]
