// static/js/vault.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Vault JS Loaded"); // Check if script runs

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
    } else {
        console.log("Show/Hide button not found");
    }

    // --- Generate Password ---
    const generateButton = document.getElementById('generate-btn');
    const passwordField = document.getElementById('entry_password');
    if (generateButton && passwordField) {
        generateButton.addEventListener('click', async function() {
            this.textContent = 'Generating...';
            this.disabled = true;
            try {
                const response = await fetch('/generate_password'); // API endpoint in Flask
                if (!response.ok) {
                     const errorData = await response.json().catch(() => ({ error: 'Failed to fetch or parse error' }));
                     throw new Error(errorData.error || `Network response was not ok (${response.status})`);
                }
                const data = await response.json();
                if (data.password) {
                    passwordField.type = 'text'; // Show generated password
                    passwordField.value = data.password;
                    if(showHideButton) showHideButton.textContent = 'Hide'; // Update button text
                    // Optionally focus the field or provide other feedback
                } else {
                    alert('Error generating password: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error fetching generated password:', error);
                alert('Could not generate password: ' + error.message);
            } finally {
                this.textContent = 'Generate';
                this.disabled = false;
            }
        });
    } else {
         console.log("Generate button or password field not found");
    }

    // --- Show Stored Password (Temporary Alert) ---
    document.querySelectorAll('.show-stored-btn').forEach(button => {
        button.addEventListener('click', async function() {
            const entryId = this.getAttribute('data-id');
            const originalText = this.textContent;
            this.textContent = '...'; // Loading indicator
            this.disabled = true;

            try {
                const response = await fetch(`/get_password/${entryId}`);
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: 'Failed to fetch or parse error' }));
                    throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                if (data.password !== undefined) { // Check if password key exists (even if empty string)
                    // Use alert for simplicity - better UI would use modal/tooltip
                    alert(`Password:\n\n${data.password || '(empty)'}\n\n(This message will disappear)`);
                } else {
                    alert('Could not retrieve password: ' + (data.error || 'No password data returned'));
                }
            } catch (error) {
                console.error('Error fetching password:', error);
                alert('Error fetching password: ' + error.message);
            } finally {
                 // Restore button state after short delay to allow user to see loading state
                 setTimeout(() => {
                    this.textContent = originalText;
                    this.disabled = false;
                 }, 300);
            }
        });
    });

    // --- Copy Stored Password ---
    document.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', async function() {
            if (!navigator.clipboard) {
                alert('Clipboard API not available in this browser or context (HTTPS required).');
                console.warn("Clipboard API unavailable.");
                return; // Stop if clipboard is not available
            }

            const entryId = this.getAttribute('data-id');
            const originalText = this.textContent;
            this.textContent = '...'; // Loading indicator
            this.disabled = true;

            try {
                const response = await fetch(`/get_password/${entryId}`);
                 if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: 'Failed to fetch or parse error' }));
                    throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
                }
                const data = await response.json();

                if (data.password !== undefined) { // Check if password key exists
                    await navigator.clipboard.writeText(data.password);
                    this.textContent = 'Copied!'; // Provide feedback
                    // Clear clipboard and restore text after a delay
                    setTimeout(() => {
                        // Attempt to clear - might fail silently in some browsers/contexts
                        navigator.clipboard.writeText('').catch(err => {});
                        this.textContent = originalText; // Restore original text
                    }, 3000); // 3 seconds feedback
                } else {
                     alert('Could not retrieve password to copy: ' + (data.error || 'No password data returned'));
                     this.textContent = originalText; // Restore immediately on error
                }
            } catch (error) {
                console.error('Error copying password:', error);
                alert('Error copying password: ' + error.message);
                this.textContent = originalText; // Restore immediately on error
            } finally {
                // Ensure button is re-enabled *after* the timeout or on error
                // The timeout above handles re-enabling on success after feedback period.
                // If there was an error, it's re-enabled immediately above.
                 if (this.textContent !== 'Copied!') { // Only re-enable immediately if not in "Copied!" state
                     this.disabled = false;
                 }
            }
        });
    });
});