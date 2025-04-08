// static/js/vault.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Vault JS Loaded"); // Check if script runs

    // --- Add/Edit Form Password Visibility ---
    const showHideButton = document.getElementById('show-hide-btn');
    if (showHideButton) {
        showHideButton.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const passwordInput = document.getElementById(targetId);
            // Logic to change type and text/icon is now handled in vault.html's inline script
            // This listener block could be removed if the inline script handles everything,
            // but keeping it ensures the basic type toggle works even if inline script fails.
             if (passwordInput) {
                if (passwordInput.type === 'password') { passwordInput.type = 'text'; }
                else { passwordInput.type = 'password'; }
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
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>'; // Loading indicator
            this.disabled = true;
            try {
                const response = await fetch('/generate_password');
                if (!response.ok) {
                     const errorData = await response.json().catch(() => ({ error: 'Failed to fetch or parse error' }));
                     throw new Error(errorData.error || `Network response was not ok (${response.status})`);
                }
                const data = await response.json();
                if (data.password) {
                    passwordField.type = 'text'; // Show generated password
                    passwordField.value = data.password;
                    // Update show/hide button state if it exists
                    if(showHideButton) {
                        showHideButton.innerHTML = `<i class="bi bi-eye-slash"></i> Hide`;
                        showHideButton.title = 'Hide Password';
                    }
                } else {
                    alert('Error generating password: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error fetching generated password:', error);
                alert('Could not generate password: ' + error.message);
            } finally {
                this.innerHTML = '<i class="bi bi-stars"></i>'; // Restore icon
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
            const icon = this.querySelector('i');
            const originalIconClass = icon ? icon.className : ''; // Store original icon
            if(icon) icon.className = 'spinner-border spinner-border-sm'; // Loading indicator
            this.disabled = true;

            try {
                const response = await fetch(`/get_password/${entryId}`);
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: 'Failed to fetch or parse error' }));
                    throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                if (data.password !== undefined) {
                    alert(`Password:\n\n${data.password || '(empty)'}\n\n(This message will disappear)`);
                } else {
                    alert('Could not retrieve password: ' + (data.error || 'No password data returned'));
                }
            } catch (error) {
                console.error('Error fetching password:', error);
                alert('Error fetching password: ' + error.message);
            } finally {
                 setTimeout(() => { // Restore after short delay
                    if(icon) icon.className = originalIconClass; // Restore icon
                    this.disabled = false;
                 }, 300);
            }
        });
    });

    // --- Copy Stored Password ---
    document.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', async function() {
            if (!navigator.clipboard) { alert('Clipboard API not available (HTTPS required).'); return; }

            const entryId = this.getAttribute('data-id');
            const icon = this.querySelector('i');
            const originalIconClass = icon ? icon.className : '';
            const originalTitle = this.title;
            if(icon) icon.className = 'spinner-border spinner-border-sm';
            this.disabled = true;

            try {
                const response = await fetch(`/get_password/${entryId}`);
                 if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: 'Failed to fetch or parse error' }));
                    throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
                }
                const data = await response.json();

                if (data.password !== undefined) {
                    await navigator.clipboard.writeText(data.password);
                    if(icon) icon.className = 'bi bi-check-lg text-success'; // Success icon
                    this.title = 'Copied!';
                    setTimeout(() => { // Restore after feedback
                        navigator.clipboard.writeText('').catch(err => {}); // Attempt to clear
                        if(icon) icon.className = originalIconClass; // Restore icon
                        this.title = originalTitle;
                        this.disabled = false;
                    }, 2000); // 2 seconds feedback
                } else {
                     alert('Could not retrieve password to copy: ' + (data.error || 'No password data returned'));
                     if(icon) icon.className = originalIconClass; // Restore immediately on error
                     this.title = originalTitle;
                     this.disabled = false;
                 }
            } catch (error) {
                console.error('Error copying password:', error);
                alert('Error copying password: ' + error.message);
                 if(icon) icon.className = originalIconClass; // Restore immediately on error
                 this.title = originalTitle;
                 this.disabled = false;
            }
            // Note: Don't re-enable here if success timeout is running
        });
    });
});