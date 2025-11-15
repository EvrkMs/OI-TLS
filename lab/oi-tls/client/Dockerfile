FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o client ./main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates iproute2 bash
WORKDIR /app
COPY --from=build /app/client /usr/local/bin/clientctl
ENTRYPOINT ["/usr/local/bin/clientctl"]
