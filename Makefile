.PHONY: build run test test-short clean modules scan demo install

BINARY=gramfuzz
MAIN=./cmd/gramfuzz

build:
	go build -ldflags "-s -w" -o $(BINARY) $(MAIN)

run: build
	./$(BINARY) modules

test:
	go vet ./...
	go test ./...

# Hermetic tests (skips the live t.me integration test) — what CI runs.
test-short:
	go vet ./...
	go test -short ./...

scan: build
	./$(BINARY) scan --bot demo_bot --webapp https://example.com/app --backend https://api.example.com --format both

demo: build
	./$(BINARY) scan

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf reports/

modules: build
	./$(BINARY) modules

install:
	go install $(MAIN)
