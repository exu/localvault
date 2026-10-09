.PHONY: build test
build:
	go build -o dist/localvault .
test:
	go test ./...
