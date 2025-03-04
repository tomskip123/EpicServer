#!/bin/bash
set -e

echo "Generating Go documentation with pkgsite..."

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

# Install pkgsite if not already installed
if ! command -v pkgsite &> /dev/null; then
  echo "Installing pkgsite..."
  go install golang.org/x/pkgsite/cmd/pkgsite@latest
fi

# Ensure go modules are downloaded
echo "Preparing Go modules..."
go mod download
go mod tidy

# Find an available port
PORT=8080
while netstat -tuln | grep ":$PORT " > /dev/null 2>&1; do
  echo "Port $PORT is in use, trying next port"
  PORT=$((PORT + 1))
done
echo "Using port $PORT for pkgsite server"

# Run pkgsite server
echo "Running pkgsite to generate static HTML..."
# In CI, ensure we're listening on all interfaces, not just loopback
if [ "$CI" = "true" ]; then
  pkgsite -http="0.0.0.0:$PORT" . &
else
  pkgsite -http=":$PORT" . &
fi
PKGSITE_PID=$!

# Allow pkgsite server to start
echo "Waiting for pkgsite server to start..."
MAX_RETRIES=60
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
  echo "Checking if process is running:"
  ps -p $PKGSITE_PID || echo "Process not found"
  echo "Checking network status:"
  netstat -tuln | grep ":$PORT" || echo "Port $PORT not listening"
  kill $PKGSITE_PID 2>/dev/null || true
  exit 1
fi

# Get module name from go.mod
MODULE_NAME=$(grep "^module" go.mod | awk '{print $2}')
echo "Module name: $MODULE_NAME"

# Create necessary directories
mkdir -p docs/static
mkdir -p docs/css
mkdir -p docs/js

# Create a simple CSS file for styling
echo "Creating basic CSS..."
cat > docs/css/style.css << 'EOF'
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
  line-height: 1.6;
  color: #333;
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}
pre, code {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  background-color: #f5f5f5;
  border-radius: 3px;
  padding: 2px 4px;
}
pre {
  padding: 16px;
  overflow: auto;
}
a {
  color: #0366d6;
  text-decoration: none;
}
a:hover {
  text-decoration: underline;
}
h1, h2, h3, h4, h5, h6 {
  margin-top: 24px;
  margin-bottom: 16px;
  font-weight: 600;
  line-height: 1.25;
}
table {
  border-collapse: collapse;
  width: 100%;
  margin-bottom: 16px;
}
table th, table td {
  border: 1px solid #ddd;
  padding: 8px;
  text-align: left;
}
table th {
  background-color: #f5f5f5;
}
EOF

# Create index.html that redirects to the package
echo "Creating index.html..."
cat > docs/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>EpicServer Documentation</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <h1>EpicServer Documentation</h1>
    <p>This is the documentation for the <a href="https://github.com/tomskip123/EpicServer">EpicServer</a> package.</p>
    
    <h2>Package Information</h2>
    <p>Module: ${MODULE_NAME}</p>
    
    <h2>Documentation</h2>
    <div id="content">Loading documentation...</div>
    
    <script>
    // Fetch the package documentation
    fetch('http://127.0.0.1:${PORT}/${MODULE_NAME}')
        .then(response => response.text())
        .then(html => {
            // Extract the main content
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const content = doc.querySelector('.Documentation-content');
            if (content) {
                document.getElementById('content').innerHTML = content.innerHTML;
            } else {
                document.getElementById('content').innerHTML = '<p>Failed to load documentation content.</p>';
            }
        })
        .catch(error => {
            document.getElementById('content').innerHTML = '<p>Error loading documentation: ' + error.message + '</p>';
        });
    </script>
</body>
</html>
EOF

# Download the EpicServer package documentation
echo "Downloading EpicServer package documentation..."
curl -s "http://127.0.0.1:$PORT/$MODULE_NAME" > docs/package.html

# Extract the main content from the HTML
echo "Extracting documentation content..."
cat > docs/js/extract.js << 'EOF'
const fs = require('fs');
const { JSDOM } = require('jsdom');

// Read the HTML file
const html = fs.readFileSync('docs/package.html', 'utf8');

// Parse the HTML
const dom = new JSDOM(html);
const document = dom.window.document;

// Extract the main content
const content = document.querySelector('.Documentation-content');
if (content) {
  // Create a standalone HTML file with the content
  const standalone = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>EpicServer Documentation</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <h1>EpicServer Documentation</h1>
    <div class="content">
      ${content.innerHTML}
    </div>
</body>
</html>
  `;
  
  fs.writeFileSync('docs/index.html', standalone);
  console.log('Documentation extracted successfully');
} else {
  console.error('Failed to extract documentation content');
  // Create a simple fallback
  const fallback = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>EpicServer Documentation</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <h1>EpicServer Documentation</h1>
    <p>This is the documentation for the EpicServer package.</p>
    <p>Please visit <a href="https://pkg.go.dev/github.com/tomskip123/EpicServer/v2">pkg.go.dev</a> for the full documentation.</p>
</body>
</html>
  `;
  
  fs.writeFileSync('docs/index.html', fallback);
}
EOF

# Try to extract content using Node.js if available
if command -v node &> /dev/null; then
  echo "Using Node.js to extract content..."
  # Install jsdom if needed
  if ! node -e "require('jsdom')" &> /dev/null; then
    if [ "$CI" = "true" ]; then
      echo "Installing jsdom..."
      npm install jsdom
    else
      echo "jsdom not found, skipping content extraction"
    fi
  fi
  
  # Run the extraction script if jsdom is available
  if node -e "require('jsdom')" &> /dev/null; then
    node docs/js/extract.js
  fi
else
  echo "Node.js not found, using simple approach..."
  # Create a simple fallback
  cat > docs/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>EpicServer Documentation</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <h1>EpicServer Documentation</h1>
    <p>This is the documentation for the <a href="https://github.com/tomskip123/EpicServer">EpicServer</a> package.</p>
    <p>Please visit <a href="https://pkg.go.dev/${MODULE_NAME}">pkg.go.dev</a> for the full documentation.</p>
    
    <h2>Package Information</h2>
    <p>Module: ${MODULE_NAME}</p>
    
    <iframe src="package.html" style="width: 100%; height: 800px; border: none;"></iframe>
</body>
</html>
EOF
fi

# Kill the pkgsite server
echo "Documentation fetching complete, stopping pkgsite server..."
kill $PKGSITE_PID 2>/dev/null || true
sleep 2  # Give process time to exit gracefully

# Fix permissions
chmod -R 755 docs/

echo "Documentation generation complete. Files are in the docs/ directory."
ls -la docs/ 