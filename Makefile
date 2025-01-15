TAG=nightly
run:
	go mod download
	go run cmd/server.go
build:
	go mod download
	go build -o bin/server cmd/server.go
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
newman-test:
	newman run tests/axes.postman_collection.json