// Put your custom JS code here

// Custom scripts
document.addEventListener('DOMContentLoaded', function() {
  // Fix search index path for GitHub Pages
  if (window.location.hostname === 'tomskip123.github.io') {
    // Override the search index URL to use the correct base path
    window.searchIndexPath = '/EpicServer/search-index.json';
    
    // Patch the FlexSearch initialization if needed
    const originalFetch = window.fetch;
    window.fetch = function(url, options) {
      if (url === '/search-index.json') {
        return originalFetch('/EpicServer/search-index.json', options);
      }
      return originalFetch(url, options);
    };
  }
});
