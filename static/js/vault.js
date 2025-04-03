// static/js/vault.js

document.addEventListener('DOMContentLoaded', function() {
    // --- Add/Edit Form Password Visibility ---
    const showHideButton = document.getElementById('show-hide-btn');
    if (showHideButton) {
        showHideButton.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const passwordInput = document.getElementById(targetId);
            if (passwordInput) {
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    this.textContent = 'Hide';
                } else {
                    passwordInput.type = 'password';
                    this.textContent = 'Show';
                }
            }
        });
    }

    // --- Generate Password ---
    const generateButton = document.getElementById('generate-btn');
    const passwordField = document.getElementById('entry_password');
    if (generateButton && passwordField) {
        generateButton.addEventListener('click', async function() {
            try {
                const response = await fetch('/generate_password'); // API endpoint in Flask
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                const data = await response.json();
                if (data.password) {
                    passwordField.type = 'text'; // Show generated password
                    passwordField.value = data.password;
                    if(showHideButton) showHideButton.textContent = 'Hide'; // Update button text
                    alert('Password generated and filled.');
                } else {
                    alert('Error generating password: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error fetching generated password:', error);
                alert('Could not generate password. See console for details.');
            }
        });
    }

    // --- Show Stored Password (Temporary) ---
    document.querySelectorAll('.show-stored-btn').forEach(button => {
        button.addEventListener('click', async function() {
            const entryId = this.getAttribute('data-id');
            const originalText = this.textContent;
            this.textContent = 'Fetching...';
            this.disabled = true;

            try {
                const response = await fetch(`/get_password/${entryId}`);
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: 'Failed to fetch or parse error' }));
                    throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                if (data.password) {
                    // Display briefly - prompt is simple, better UI would use a temporary overlay
                    alert(`Password for this entry:\n\n${data.password}\n\n(This message will disappear)`);
                } else {
                    alert('Could not retrieve password: ' + (data.error || 'No password returned'));
                }
            } catch (error) {
                console.error('Error fetching password:', error);
                alert('Error fetching password: ' + error.message);
            } finally {
                 // Restore button state after a short delay
                 setTimeout(() => {
                    this.textContent = originalText;
                    this.disabled = false;
                 }, 500);
            }
        });
    });

    // --- Copy Stored Password ---
    document.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', async function() {
            const entryId = this.getAttribute('data-id');
            const originalText = this.textContent;
            this.textContent = 'Copying...';
            this.disabled = true;

            try {
                const response = await fetch(`/get_password/${entryId}`);
                 if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: 'Failed to fetch or parse error' }));
                    throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
                }
                const data = await response.json();

                if (data.password && navigator.clipboard) {
                    await navigator.clipboard.writeText(data.password);
                    alert('Password copied to clipboard!');
                    // Clear clipboard after a delay (optional security measure)
                    // Note: Browser support/permissions for clipboard clearing can vary
                    setTimeout(() => {
                       // Attempt to clear - might not work in all contexts
                       navigator.clipboard.writeText('').catch(err => console.log("Clipboard clear ignored/failed:", err));
                    }, 15000); // 15 seconds
                } else if (!navigator.clipboard) {
                     alert('Clipboard API not available in this browser or context (e.g., HTTP).');
                     console.warn("Clipboard API unavailable.");
                }
                 else {
                     alert('Could not retrieve password to copy: ' + (data.error || 'No password returned'));
                 }
            } catch (error) {
                console.error('Error copying password:', error);
                alert('Error copying password: ' + error.message);
            } finally {
                // Restore button state after a short delay
                setTimeout(() => {
                    this.textContent = originalText;
                    this.disabled = false;
                 }, 500);
            }
        });
    });
});