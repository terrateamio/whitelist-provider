.PHONY: build test clean

build:
	go build -o whitelist-provider .

test:
	go test ./...

clean:
	rm -f whitelist-provider whitelist-provider-*
