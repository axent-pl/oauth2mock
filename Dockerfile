FROM golang:1.21.4

WORKDIR /app
COPY / /app/
RUN go mod download && make build

EXPOSE 8080
VOLUME [ "/app/data"]
ENTRYPOINT [ "/app/bin/server" ]