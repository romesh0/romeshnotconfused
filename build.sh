#!/bin/bash
set -e

echo "🔨 Building RomeshNotConfused Scanner..."

# Build for multiple platforms
PLATFORMS="linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64"

for platform in $PLATFORMS; do
    GOOS=${platform%/*}
    GOARCH=${platform#*/}
    
    output_name="romeshnotconfused-${GOOS}-${GOARCH}"
    if [ $GOOS = "windows" ]; then
        output_name+='.exe'
    fi
    
    echo "Building for $GOOS/$GOARCH..."
    GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o dist/$output_name ./cmd/romeshnotconfused
done

echo "✅ Build complete! Binaries in ./dist/"
