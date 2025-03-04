// Simple JavaScript for the static website
document.addEventListener('DOMContentLoaded', function() {
    // Add a timestamp to the footer
    const footer = document.querySelector('.footer');
    if (footer) {
        const timestamp = document.createElement('p');
        timestamp.textContent = 'Page loaded at: ' + new Date().toLocaleString();
        timestamp.style.fontSize = '0.8em';
        timestamp.style.marginTop = '10px';
        footer.appendChild(timestamp);
    }
    
    // Add click event to buttons
    const buttons = document.querySelectorAll('button');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            alert('Button clicked! This alert is from script.js');
        });
    });
    
    // Log a message to the console
    console.log('EpicServer static site loaded successfully!');
}); 