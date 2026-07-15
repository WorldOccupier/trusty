.PHONY: build build-time vet test test-race bench clean time-build time-test \
        profile-cpu profile-mem profile-trace bench-compare

BIN_NAME   := trusty
CMD_DIR    := ./cmd/trusty
PROFILE_DIR:= ./profiles

# ─── Build ──────────────────────────────────────────────────────────────

build:
	go build -o $(BIN_NAME) $(CMD_DIR)

build-release:
	go build -o $(BIN_NAME) -ldflags="-s -w -X main.version=$(VERSION)" $(CMD_DIR)
	@echo "Built $(BIN_NAME) (stripped, $(VERSION))"
	@ls -lh $(BIN_NAME)

build-time:
	@echo "=== Build Timing ==="
	@/usr/bin/time go build -o $(BIN_NAME) $(CMD_DIR) 2>&1

build-verbose:
	go build -v -o $(BIN_NAME) $(CMD_DIR) 2>&1

install:
	go install $(CMD_DIR)

# ─── Test ───────────────────────────────────────────────────────────────

test:
	go test ./... -count=1 2>&1

test-race:
	go test ./... -race -count=1 2>&1

test-verbose:
	go test ./... -v -count=1 2>&1

test-short:
	go test ./... -short -count=1 2>&1

test-pkg:
	go test $(PKG) -v -count=1 2>&1

bench:
	go test ./... -bench=. -benchmem -count=1 2>&1

bench-compare:
	go test ./... -bench=. -benchmem -count=5 -benchtime=100ms > /tmp/bench.txt 2>&1

# ─── Timing ─────────────────────────────────────────────────────────────

time-build:
	@echo "=== Build Time ==="
	@echo "Cold build (no cache):"
	@go clean -cache 2>/dev/null; /usr/bin/time go build -o $(BIN_NAME) $(CMD_DIR) 2>&1 | tail -3
	@echo ""
	@echo "Warm build (with cache):"
	@/usr/bin/time go build -o $(BIN_NAME) $(CMD_DIR) 2>&1 | tail -3

time-test:
	@echo "=== Test Timing ==="
	@echo "Cold tests (no cache):"
	@go clean -testcache 2>/dev/null; /usr/bin/time go test ./... -count=1 2>&1 | tail -5
	@echo ""
	@echo "Warm tests (cached):"
	@/usr/bin/time go test ./... -count=1 2>&1 | tail -5

# ─── Profiling ──────────────────────────────────────────────────────────

$(PROFILE_DIR):
	mkdir -p $(PROFILE_DIR)

profile-cpu: $(PROFILE_DIR)
	go test ./internal/scanner -bench=. -benchmem \
		-cpuprofile $(PROFILE_DIR)/cpu.pprof \
		-memprofile $(PROFILE_DIR)/mem.pprof \
		-count=1 2>&1
	@echo "CPU profile:  $(PROFILE_DIR)/cpu.pprof"
	@echo "Memory profile: $(PROFILE_DIR)/mem.pprof"
	@echo "View: go tool pprof $(PROFILE_DIR)/cpu.pprof"

profile-mem: $(PROFILE_DIR)
	go test ./... -bench=. -benchmem \
		-memprofile $(PROFILE_DIR)/mem.pprof \
		-memprofilerate 1 \
		-count=1 2>&1
	@echo "Memory profile: $(PROFILE_DIR)/mem.pprof"

profile-trace: $(PROFILE_DIR)
	go test ./... -trace=$(PROFILE_DIR)/trace.out -count=1 2>&1
	@echo "Trace: $(PROFILE_DIR)/trace.out"
	@echo "View: go tool trace $(PROFILE_DIR)/trace.out"

profile-web: $(PROFILE_DIR)
	@which pprof 2>/dev/null || go install github.com/google/pprof@latest
	@echo "Opening CPU profile in browser..."
	-go tool pprof -http=:8081 $(PROFILE_DIR)/cpu.pprof 2>/dev/null

# ─── Clean ──────────────────────────────────────────────────────────────

clean:
	rm -f $(BIN_NAME)
	rm -rf $(PROFILE_DIR)
	go clean -cache -testcache

# ─── Lint ───────────────────────────────────────────────────────────────

vet:
	go vet ./...

lint:
	@which golangci-lint 2>/dev/null || (echo "Install golangci-lint: brew install golangci-lint"; exit 1)
	golangci-lint run ./...

# ─── Size analysis ──────────────────────────────────────────────────────

files:
	@find . -name '*.go' -not -path './.git/*' | sort | while read f; do \
		lines=$$(wc -l < "$$f"); \
		printf "%5d %s\n" "$$lines" "$$f"; \
	done | sort -rn | head -20

coverage:
	go test ./... -coverprofile=$(PROFILE_DIR)/coverage.out -count=1 2>&1
	go tool cover -func=$(PROFILE_DIR)/coverage.out | tail -5
	@echo ""
	@echo "Open in browser: go tool cover -html=$(PROFILE_DIR)/coverage.out"

# ─── Help ───────────────────────────────────────────────────────────────

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Build:"
	@echo "  build          Build the binary"
	@echo "  build-time     Build with timing output"
	@echo "  install        Install to GOPATH/bin"
	@echo ""
	@echo "Test:"
	@echo "  test           Run all tests"
	@echo "  test-race      Run tests with race detector"
	@echo "  bench          Run benchmarks"
	@echo "  coverage       Run tests with coverage"
	@echo ""
	@echo "Timing:"
	@echo "  time-build     Time cold and warm builds"
	@echo "  time-test      Time cold and warm test runs"
	@echo ""
	@echo "Profiling:"
	@echo "  profile-cpu    Generate CPU profile (scanner benchmarks)"
	@echo "  profile-mem    Generate memory profile"
	@echo "  profile-trace  Generate execution trace"
	@echo "  profile-web    Open CPU profile in browser"
	@echo ""
	@echo "Quality:"
	@echo "  vet            Run go vet"
	@echo "  lint           Run golangci-lint"
	@echo "  files          Show largest Go files"
	@echo ""
	@echo "Clean:"
	@echo "  clean          Remove binary, profiles, caches"
