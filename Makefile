# Makefile for sim_reader cross-compilation via Docker
# Supports: Linux, macOS, Windows

APP_NAME = sim_reader
VERSION = 2.0.0
BUILD_DIR = build

# Default target
.PHONY: all
all: build-all

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# ============================================================================
# BUILD ALL PLATFORMS
# ============================================================================

.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows
	@echo ""
	@echo "========================================="
	@echo "Build complete! Binaries in $(BUILD_DIR)/"
	@echo "========================================="
	@ls -la $(BUILD_DIR)/

# ============================================================================
# LINUX BUILDS
# ============================================================================

.PHONY: build-linux
build-linux: build-linux-amd64 build-linux-arm64

.PHONY: build-linux-amd64
build-linux-amd64: $(BUILD_DIR)
	@echo "Building for Linux amd64..."
	docker run --rm \
		-v "$(PWD)":/app \
		-w /app \
		-e CGO_ENABLED=1 \
		-e GOOS=linux \
		-e GOARCH=amd64 \
		golang:1.21 \
		sh -c "apt-get update -qq && apt-get install -y -qq libpcsclite-dev >/dev/null 2>&1 && \
		       go build -ldflags='-s -w' -o $(BUILD_DIR)/$(APP_NAME)_linux_amd64 ."
	@echo "✓ Linux amd64 done"

.PHONY: build-linux-arm64
build-linux-arm64: $(BUILD_DIR)
	@echo "Building for Linux arm64..."
	docker run --rm \
		-v "$(PWD)":/app \
		-w /app \
		-e CGO_ENABLED=1 \
		-e GOOS=linux \
		-e GOARCH=arm64 \
		-e CC=aarch64-linux-gnu-gcc \
		golang:1.21 \
		sh -c "apt-get update -qq && apt-get install -y -qq gcc-aarch64-linux-gnu libpcsclite-dev >/dev/null 2>&1 && \
		       go build -ldflags='-s -w' -o $(BUILD_DIR)/$(APP_NAME)_linux_arm64 ."
	@echo "✓ Linux arm64 done"

# ============================================================================
# MACOS BUILDS (using osxcross in Docker)
# ============================================================================

.PHONY: build-darwin
build-darwin: build-darwin-amd64 build-darwin-arm64

.PHONY: build-darwin-amd64
build-darwin-amd64: $(BUILD_DIR)
	@echo "Building for macOS amd64 (Intel)..."
	docker run --rm \
		-v "$(PWD)":/app \
		-w /app \
		-e CGO_ENABLED=1 \
		-e GOOS=darwin \
		-e GOARCH=amd64 \
		-e CC=o64-clang \
		-e CXX=o64-clang++ \
		crazymax/osxcross:latest-ubuntu \
		sh -c "apt-get update -qq && apt-get install -y -qq golang >/dev/null 2>&1 && \
		       go build -ldflags='-s -w' -o $(BUILD_DIR)/$(APP_NAME)_darwin_amd64 ."
	@echo "✓ macOS amd64 done"

.PHONY: build-darwin-arm64
build-darwin-arm64: $(BUILD_DIR)
	@echo "Building for macOS arm64 (Apple Silicon)..."
	docker run --rm \
		-v "$(PWD)":/app \
		-w /app \
		-e CGO_ENABLED=1 \
		-e GOOS=darwin \
		-e GOARCH=arm64 \
		-e CC=oa64-clang \
		-e CXX=oa64-clang++ \
		crazymax/osxcross:latest-ubuntu \
		sh -c "apt-get update -qq && apt-get install -y -qq golang >/dev/null 2>&1 && \
		       go build -ldflags='-s -w' -o $(BUILD_DIR)/$(APP_NAME)_darwin_arm64 ."
	@echo "✓ macOS arm64 done"

# ============================================================================
# WINDOWS BUILD (using mingw)
# ============================================================================

.PHONY: build-windows
build-windows: $(BUILD_DIR)
	@echo "Building for Windows amd64..."
	docker run --rm \
		-v "$(PWD)":/app \
		-w /app \
		-e CGO_ENABLED=1 \
		-e GOOS=windows \
		-e GOARCH=amd64 \
		-e CC=x86_64-w64-mingw32-gcc \
		golang:1.21 \
		sh -c "apt-get update -qq && apt-get install -y -qq gcc-mingw-w64-x86-64 >/dev/null 2>&1 && \
		       go build -ldflags='-s -w' -o $(BUILD_DIR)/$(APP_NAME)_windows_amd64.exe ."
	@echo "✓ Windows amd64 done"

# ============================================================================
# UTILITIES
# ============================================================================

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(APP_NAME) $(APP_NAME).exe

.PHONY: list help
list help:
	@echo "sim_reader build system (Docker-based)"
	@echo ""
	@echo "Available targets:"
	@echo "  make build-all          - Build for ALL platforms"
	@echo ""
	@echo "  make build-linux        - Linux amd64 + arm64"
	@echo "  make build-linux-amd64  - Linux x64 only"
	@echo "  make build-linux-arm64  - Linux ARM64 only"
	@echo ""
	@echo "  make build-darwin       - macOS Intel + Apple Silicon"
	@echo "  make build-darwin-amd64 - macOS Intel only"
	@echo "  make build-darwin-arm64 - macOS Apple Silicon only"
	@echo ""
	@echo "  make build-windows      - Windows x64"
	@echo ""
	@echo "  make clean              - Remove build artifacts"
	@echo ""
	@echo "Output directory: $(BUILD_DIR)/"
