// Put your custom JS code here

// Custom scripts
document.addEventListener('DOMContentLoaded', function() {
  // Fix search index path for GitHub Pages
  if (window.location.hostname === 'tomskip123.github.io') {
    // Find all script elements that might be loading the search index
    const searchScripts = document.querySelectorAll('script');
    
    // Monitor for FlexSearch initialization
    const originalFlexSearchInit = window.initFlexSearch;
    if (typeof originalFlexSearchInit === 'function') {
      window.initFlexSearch = function(options) {
        // Ensure the search index path is correct
        if (options && options.indexUrl && options.indexUrl === '/search-index.json') {
          options.indexUrl = '/EpicServer/search-index.json';
        }
        return originalFlexSearchInit(options);
      };
    }
    
    // Patch fetch for direct requests
    const originalFetch = window.fetch;
    window.fetch = function(url, options) {
      if (typeof url === 'string' && url.endsWith('/search-index.json')) {
        return originalFetch('/EpicServer/search-index.json', options);
      }
      return originalFetch(url, options);
    };
  }
});
