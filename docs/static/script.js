// EpicServer Documentation JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Add timestamp to footer
    const footer = document.querySelector('.footer');
    if (footer) {
        const timestamp = document.createElement('p');
        timestamp.textContent = 'Last updated: ' + new Date().toLocaleString();
        timestamp.style.fontSize = '0.85rem';
        timestamp.style.opacity = '0.7';
        footer.appendChild(timestamp);
    }

    // Add copy functionality to code blocks
    const codeBlocks = document.querySelectorAll('pre');
    codeBlocks.forEach(function(block) {
        const copyButton = document.createElement('button');
        copyButton.textContent = 'Copy';
        copyButton.className = 'copy-button';
        
        // Make the pre position relative for absolute positioning of the button
        block.style.position = 'relative';
        
        block.appendChild(copyButton);
        
        copyButton.addEventListener('click', function() {
            const code = block.querySelector('code') 
                ? block.querySelector('code').textContent 
                : block.textContent;
                
            navigator.clipboard.writeText(code).then(function() {
                copyButton.textContent = 'Copied!';
                copyButton.style.backgroundColor = 'var(--color-success)';
                
                setTimeout(function() {
                    copyButton.textContent = 'Copy';
                    copyButton.style.backgroundColor = '';
                }, 2000);
            }).catch(function(err) {
                console.error('Could not copy text: ', err);
                copyButton.textContent = 'Error';
                copyButton.style.backgroundColor = 'var(--color-error)';
                
                setTimeout(function() {
                    copyButton.textContent = 'Copy';
                    copyButton.style.backgroundColor = '';
                }, 2000);
            });
        });
    });

    // Add collapsible sections
    const collapsibleHeadings = document.querySelectorAll('.collapsible');
    collapsibleHeadings.forEach(function(heading) {
        heading.style.cursor = 'pointer';
        
        // Add indicator
        const indicator = document.createElement('span');
        indicator.textContent = ' ▼';
        indicator.style.fontSize = '0.8em';
        indicator.style.marginLeft = '0.5rem';
        indicator.style.opacity = '0.7';
        heading.appendChild(indicator);
        
        // Get the content to collapse (all elements until next heading of same or higher level)
        const contentElements = [];
        let nextElement = heading.nextElementSibling;
        
        while (nextElement && 
               !(nextElement.tagName === heading.tagName || 
                 (heading.tagName === 'H3' && ['H1', 'H2'].includes(nextElement.tagName)) ||
                 (heading.tagName === 'H4' && ['H1', 'H2', 'H3'].includes(nextElement.tagName)))) {
            contentElements.push(nextElement);
            nextElement = nextElement.nextElementSibling;
        }
        
        // Add click handler
        heading.addEventListener('click', function() {
            contentElements.forEach(function(element) {
                element.style.display = element.style.display === 'none' ? '' : 'none';
            });
            
            indicator.textContent = indicator.textContent === ' ▼' ? ' ▶' : ' ▼';
        });
    });

    // Add smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                // Add offset for fixed header
                const headerOffset = 70;
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;
                
                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
                
                // Update URL without page reload
                history.pushState(null, null, targetId);
            }
        });
    });

    // Highlight current page in navigation
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav a');
    
    navLinks.forEach(function(link) {
        const linkPath = link.getAttribute('href');
        const currentFile = currentPath.split('/').pop() || 'index.html';
        
        if (linkPath === currentFile) {
            link.classList.add('active');
        }
    });

    // Add table of contents generation if element exists
    const tocContainer = document.querySelector('.toc-dynamic');
    if (tocContainer) {
        const headings = document.querySelectorAll('h2, h3');
        const toc = document.createElement('ul');
        
        headings.forEach(function(heading) {
            // Create an ID for the heading if it doesn't have one
            if (!heading.id) {
                heading.id = heading.textContent.toLowerCase().replace(/[^\w]+/g, '-');
            }
            
            const listItem = document.createElement('li');
            const link = document.createElement('a');
            
            link.href = '#' + heading.id;
            link.textContent = heading.textContent;
            
            // Indent h3 elements
            if (heading.tagName === 'H3') {
                listItem.style.marginLeft = '1rem';
                listItem.style.fontSize = '0.9rem';
            }
            
            listItem.appendChild(link);
            toc.appendChild(listItem);
        });
        
        tocContainer.appendChild(toc);
    }
    
    // Add link icon to heading anchors on hover
    document.querySelectorAll('h2, h3, h4, h5, h6').forEach(heading => {
        if (heading.id) {
            heading.style.position = 'relative';
            
            const anchor = document.createElement('a');
            anchor.className = 'heading-anchor';
            anchor.href = '#' + heading.id;
            anchor.innerHTML = '&#128279;'; // Link symbol
            anchor.style.position = 'absolute';
            anchor.style.marginLeft = '0.5rem';
            anchor.style.opacity = '0';
            anchor.style.fontSize = '0.8em';
            anchor.style.transition = 'opacity 0.2s';
            anchor.style.textDecoration = 'none';
            
            heading.appendChild(anchor);
            
            heading.addEventListener('mouseover', () => {
                anchor.style.opacity = '0.5';
            });
            
            heading.addEventListener('mouseout', () => {
                anchor.style.opacity = '0';
            });
        }
    });
}); 