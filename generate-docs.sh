#!/bin/bash
set -e

echo "Generating Go documentation..."

# Create docs directory if it doesn't exist
mkdir -p docs

# Clean any existing documentation
rm -rf docs/*

# For GitHub actions, install dependencies
if [ "$CI" = "true" ]; then
  echo "Running in CI environment, ensuring dependencies are installed..."
  # Install curl and wget if needed
  command -v curl > /dev/null || { echo "Installing curl..."; sudo apt-get update && sudo apt-get install -y curl; }
  command -v wget > /dev/null || { echo "Installing wget..."; sudo apt-get update && sudo apt-get install -y wget; }
fi

# Ensure go modules are downloaded
echo "Preparing Go modules..."
go mod download
go mod tidy

# Find an available port (sometimes 6060 might be occupied in CI)
PORT=6060
while netstat -tuln | grep ":$PORT " > /dev/null 2>&1; do
  echo "Port $PORT is in use, trying next port"
  PORT=$((PORT + 1))
done
echo "Using port $PORT for godoc server"

# Run godoc without specifying templates
echo "Running godoc to generate static HTML..."
# In CI, ensure we're listening on all interfaces, not just loopback
if [ "$CI" = "true" ]; then
  # Use -goroot . to ensure godoc serves current directory in module mode
  godoc -http="0.0.0.0:$PORT" -index -goroot . &
else
  godoc -http=":$PORT" -index -goroot . &
fi
GODOC_PID=$!

# Allow godoc server to start with a more robust check
echo "Waiting for godoc server to start..."
MAX_RETRIES=60  # Longer timeout for CI
RETRY_COUNT=0
SERVER_READY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  # Try both localhost and 127.0.0.1 explicit IP
  if curl -s --head --connect-timeout 2 "http://127.0.0.1:$PORT/" > /dev/null; then
    SERVER_READY=true
    echo "Godoc server is up and running at http://127.0.0.1:$PORT/"
    break
  fi
  echo "Waiting for godoc server... (${RETRY_COUNT}/${MAX_RETRIES})"
  sleep 2  # Longer sleep in CI
  RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [ "$SERVER_READY" != "true" ]; then
  echo "Error: Godoc server failed to start after ${MAX_RETRIES} seconds"
  echo "Checking if process is running:"
  ps -p $GODOC_PID || echo "Process not found"
  echo "Checking network status:"
  netstat -tuln | grep ":$PORT" || echo "Port $PORT not listening"
  kill $GODOC_PID 2>/dev/null || true
  exit 1
fi

# Check what URLs are actually available from godoc
echo "Checking available documentation paths..."
curl -s "http://127.0.0.1:$PORT/" | grep -o 'href="[^"]*"' | sed 's/href="//' | sed 's/"//'

# Assuming module path is github.com/tomskip123/EpicServer/v2
MODULE_PATH="github.com/tomskip123/EpicServer/v2"
DOC_URL="http://127.0.0.1:$PORT/"

# Check if /pkg path exists
if curl -s --head "http://127.0.0.1:$PORT/pkg/" | grep -q "200 OK"; then
  echo "Found /pkg/ path"
  DOC_URL="http://127.0.0.1:$PORT/pkg/"
elif curl -s --head "http://127.0.0.1:$PORT/src/$MODULE_PATH/" | grep -q "200 OK"; then
  echo "Found /src/$MODULE_PATH/ path"
  DOC_URL="http://127.0.0.1:$PORT/src/$MODULE_PATH/"
elif curl -s --head "http://127.0.0.1:$PORT/mod/$MODULE_PATH/" | grep -q "200 OK"; then
  echo "Found /mod/$MODULE_PATH/ path"
  DOC_URL="http://127.0.0.1:$PORT/mod/$MODULE_PATH/"
fi

echo "Using documentation URL: $DOC_URL"

# Create index.html that redirects to the package
echo '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0; url=pkg/github.com/tomskip123/EpicServer/v2/index.html">
    <title>Go Documentation</title>
</head>
<body>
    <p>Redirecting to <a href="pkg/github.com/tomskip123/EpicServer/v2/index.html">documentation</a>...</p>
</body>
</html>' > docs/index.html

# Create directory structure
mkdir -p docs/pkg
mkdir -p docs/lib/godoc
mkdir -p docs/pkg/github.com/tomskip123/EpicServer/v2

# Fetch the documentation
echo "Fetching generated documentation..."

# First, download the root document to see what URLs are available
echo "Downloading root document to analyze..."
curl -s "http://127.0.0.1:$PORT/" > docs/godoc_root.html

# Use wget - we ensure it's installed earlier for CI
echo "Using wget to mirror documentation..."
wget --recursive --no-parent --convert-links --page-requisites --no-host-directories \
  --directory-prefix=docs/ --adjust-extension \
  --timeout=30 --tries=5 --waitretry=5 --no-check-certificate \
  "$DOC_URL"

# Check if wget was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to download documentation with wget"
  
  # Try to download directly
  echo "Attempting to fetch directly with curl to diagnose:"
  curl -v "$DOC_URL" || echo "Failed to connect with curl too"
  
  # Try to list all mod directories
  echo "Listing available modules:"
  curl -s "http://127.0.0.1:$PORT/mod/" | grep -o 'href="[^"]*"' || echo "No modules found"
  
  echo "Processes listening on port $PORT:"
  lsof -i :$PORT || echo "No process found with lsof"
  
  # As a fallback, try to mirror the entire site
  echo "Trying to mirror the entire site as a fallback..."
  wget --recursive --no-parent --convert-links --page-requisites --no-host-directories \
    --directory-prefix=docs/ --adjust-extension \
    --timeout=30 --tries=3 --waitretry=5 --no-check-certificate \
    "http://127.0.0.1:$PORT/"
  
  # Even if the fallback fails, continue without exiting
  echo "Continuing with whatever documentation was successfully downloaded..."
fi

# Kill the godoc server
echo "Documentation fetching complete, stopping godoc server..."
kill $GODOC_PID 2>/dev/null || true
sleep 2  # Give process time to exit gracefully

# Copy any additional documentation images or assets
if [ -d "docs-assets" ]; then
  cp -r docs-assets/* docs/
fi

echo "Documentation generation complete. Files are in the docs/ directory."
ls -la docs/ 