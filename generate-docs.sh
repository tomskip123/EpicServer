#!/bin/bash
set -e

echo "Generating Go documentation..."

# Create docs directory if it doesn't exist
mkdir -p docs

# Clean any existing documentation
rm -rf docs/*

# Run godoc without specifying templates
echo "Running godoc to generate static HTML..."
godoc -http=":6060" -index &
GODOC_PID=$!

# Allow godoc server to start
sleep 3

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

# For GitHub actions, make sure wget is installed
if [ "$CI" = "true" ] && ! command -v wget > /dev/null; then
  echo "Installing wget in CI environment..."
  sudo apt-get update && sudo apt-get install -y wget
fi

# Use wget if available
if command -v wget > /dev/null; then
  echo "Using wget to mirror documentation..."
  wget --recursive --no-parent --convert-links --page-requisites --no-host-directories \
    --directory-prefix=docs/ --adjust-extension \
    http://localhost:6060/pkg/
else
  # Fallback to curl for basic fetching
  echo "Using curl to fetch documentation (limited functionality)..."
  
  # Main package index
  curl -s http://localhost:6060/pkg/ > docs/pkg/index.html
  
  # Project-specific documentation
  curl -s http://localhost:6060/pkg/github.com/tomskip123/EpicServer/v2/ > docs/pkg/github.com/tomskip123/EpicServer/v2/index.html
  
  # Static assets
  curl -s http://localhost:6060/lib/godoc/style.css > docs/lib/godoc/style.css
  curl -s http://localhost:6060/lib/godoc/jquery.js > docs/lib/godoc/jquery.js
  curl -s http://localhost:6060/lib/godoc/godocs.js > docs/lib/godoc/godocs.js
  
  echo "Warning: Documentation may be incomplete when using curl. Install wget for better results."
fi

# Kill the godoc server
kill $GODOC_PID

# Copy any additional documentation images or assets
if [ -d "docs-assets" ]; then
  cp -r docs-assets/* docs/
fi

echo "Documentation generation complete. Files are in the docs/ directory." 