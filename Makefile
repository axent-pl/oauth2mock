build:
	go build -o bin/server main.go
newman-test:
	newman run tests/axes.postman_collection.json