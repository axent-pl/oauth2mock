FROM golang:1.23.4

WORKDIR /app
COPY / /app/
RUN make build

EXPOSE 8080
VOLUME [ "/app/data"]
ENTRYPOINT [ "/app/bin/server" ]