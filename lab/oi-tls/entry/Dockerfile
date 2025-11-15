FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o entry ./main.go

FROM alpine:3.19
WORKDIR /app
COPY --from=build /app/entry /usr/local/bin/entry
COPY certs /app/certs
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/entry"]
