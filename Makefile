BIN := bin/tsumuji-helper

.PHONY: build test vet run-plain clean

build:
	cd helper && go build -o ../$(BIN) .

test:
	cd helper && go test ./...

vet:
	cd helper && go vet ./... && gofmt -l .

# Plaintext bring-up mode: answer every EV with a fixed string.
run-plain: build
	./$(BIN) serve --insecure-text "hello from tsumuji helper"

# Authenticated mode (requires `pair` and `set-password` first).
run: build
	./$(BIN) serve

clean:
	rm -rf bin
