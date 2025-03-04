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
