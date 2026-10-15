.PHONY lib build test clean

BIN_DIR=bin

lib:
	@mkdir -p $(BIN_DIR)
	@go build -o $(BIN_DIR)/rc4.a -buildmode=archive

build:
	@go build ./...

test:
	@go test -v ./...

clean:
	@rm -rf $(BIN_DIR)
