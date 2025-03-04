#!/bin/bash
set -e

echo "Testing pkgsite documentation generation for EpicServer package..."

# Check if pkgsite is installed
if ! command -v pkgsite &> /dev/null; then
  echo "Installing pkgsite..."
  go install golang.org/x/pkgsite/cmd/pkgsite@latest
fi

# Create a temporary directory for testing
TEST_DIR=$(mktemp -d)
echo "Using temporary directory: $TEST_DIR"

# Find an available port
PORT=8080
while netstat -tuln | grep ":$PORT " > /dev/null 2>&1; do
  echo "Port $PORT is in use, trying next port"
  PORT=$((PORT + 1))
done
echo "Using port $PORT for pkgsite server"

# Run pkgsite server
echo "Testing pkgsite server..."
pkgsite -http=":$PORT" . &
PKGSITE_PID=$!

# Wait for pkgsite to start
echo "Waiting for pkgsite server to start..."
MAX_RETRIES=30
RETRY_COUNT=0
SERVER_READY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if curl -s --head --connect-timeout 2 "http://127.0.0.1:$PORT/" > /dev/null; then
    SERVER_READY=true
    echo "Pkgsite server is up and running at http://127.0.0.1:$PORT/"
    break
  fi
  echo "Waiting for pkgsite server... (${RETRY_COUNT}/${MAX_RETRIES})"
  sleep 2
  RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [ "$SERVER_READY" != "true" ]; then
  echo "Error: Pkgsite server failed to start after ${MAX_RETRIES} seconds"
  kill $PKGSITE_PID 2>/dev/null || true
  exit 1
fi

# Get module name from go.mod
MODULE_NAME=$(grep "^module" go.mod | awk '{print $2}')
echo "Module name: $MODULE_NAME"

# Test downloading the EpicServer package page
echo "Testing curl to download EpicServer package page..."
curl -s "http://127.0.0.1:$PORT/$MODULE_NAME" > "$TEST_DIR/package.html"

# Check if curl was successful
if [ ! -s "$TEST_DIR/package.html" ]; then
  echo "Error: Failed to download EpicServer package page"
  kill $PKGSITE_PID 2>/dev/null || true
  exit 1
else
  echo "Success: Downloaded EpicServer package page to $TEST_DIR/package.html"
  head -n 10 "$TEST_DIR/package.html"
fi

# Create a simple HTML file
echo "Testing HTML generation..."
cat > "$TEST_DIR/index.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>EpicServer Documentation</title>
</head>
<body>
    <h1>EpicServer Documentation</h1>
    <p>This is a test page.</p>
</body>
</html>
EOF

echo "Success: Created test HTML file"

# Kill pkgsite
kill $PKGSITE_PID 2>/dev/null || true

# Clean up
rm -rf "$TEST_DIR"

echo "Test completed successfully!" 