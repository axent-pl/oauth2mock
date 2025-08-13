TAG=nightly

build:
	go mod download
	go build -o bin/keygen cmd/keygen/main.go
	go build -o bin/server cmd/server/main.go
	go build -o bin/yaml2json cmd/yaml2json/main.go
	go build -o bin/json2yaml cmd/json2yaml/main.go

run-keygen:
	go mod download
	env KEY_TYPE="RSA256" KEY_PATH="assets/key/key.rsa256.pem" go run cmd/keygen/main.go
	env KEY_TYPE="RSA384" KEY_PATH="assets/key/key.rsa384.pem" go run cmd/keygen/main.go
	env KEY_TYPE="RSA512" KEY_PATH="assets/key/key.rsa512.pem" go run cmd/keygen/main.go
	env KEY_TYPE="P-256" KEY_PATH="assets/key/key.p-256.pem" go run cmd/keygen/main.go
	env KEY_TYPE="P-384" KEY_PATH="assets/key/key.p-384.pem" go run cmd/keygen/main.go
	env KEY_TYPE="P-521" KEY_PATH="assets/key/key.p-521.pem" go run cmd/keygen/main.go
	env KEY_TYPE="RSA256" KEY_PATH="assets/key/cert.key.rsa256.pem" CERT_PATH="assets/key/cert.cert.rsa256.pem" go run cmd/certgen/main.go
	env KEY_TYPE="RSA384" KEY_PATH="assets/key/cert.key.rsa384.pem" CERT_PATH="assets/key/cert.cert.rsa384.pem" go run cmd/certgen/main.go
	env KEY_TYPE="RSA512" KEY_PATH="assets/key/cert.key.rsa512.pem" CERT_PATH="assets/key/cert.cert.rsa512.pem" go run cmd/certgen/main.go

run-proxy:
	go mod download
	go run cmd/proxy/main.go

run:
	go mod download
	go run cmd/server/main.go

test:
	go test ./...

test-e2e:
	newman run tests/axes.postman_collection.json

run-test:
	go mod download
	go run cmd/server/main.go &
	sleep 2
	$(MAKE) test-e2e
	$(MAKE) kill-server

kill-server:
	lsof -ti:8222 | xargs kill -9

container-build: run-keygen
	docker build . -t prond/axes:$(TAG)

container-scan:
	docker scout quickview

container-cves:
	docker scout cves local://prond/axes:$(TAG)

container-build-push: run-keygen
	docker build . -t prond/axes:$(TAG)
	docker push prond/axes:$(TAG)

container-push:
	docker push prond/axes:$(TAG)

documentation:
	docker run -it --rm -p 8088:8080 -v ./docs:/usr/local/structurizr structurizr/lite:2025.03.28
