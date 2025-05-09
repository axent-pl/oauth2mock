TAG=nightly

build:
	go mod download
	go build -o bin/keygen cmd/keygen/main.go
	go build -o bin/server cmd/server/main.go

run:
	go mod download
	go run cmd/keygen/main.go
	go run cmd/server/main.go

test:
	go test ./...
test-e2e:
	newman run tests/axes.postman_collection.json


container-build:
	docker build . -t prond/axes:$(TAG)
container-scan:
	docker scout quickview
container-cves:
	docker scout cves local://prond/axes:$(TAG)
container-build-push:
	docker build . -t prond/axes:$(TAG)
	docker push prond/axes:$(TAG)
container-push:
	docker push prond/axes:$(TAG)

documentation:
	docker run -it --rm -p 8080:8080 -v ./docs:/usr/local/structurizr structurizr/lite:2025.03.28
