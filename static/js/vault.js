// static/js/vault.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault JS Loaded");

    // --- Password Generator Button (Placeholder Action) ---
    const generatePasswordActionButton = document.getElementById('generate-password-action-btn');
    const generatedPasswordTextSpan = document.getElementById('generated-password-text');
    if (generatePasswordActionButton && generatedPasswordTextSpan) {
        generatePasswordActionButton.addEventListener('click', async function() {
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Generating...';
            this.disabled = true;
            try {
                const response = await fetch('/generate_password');
                if (!response.ok) throw new Error('Failed to generate');
                const data = await response.json();
                if (data.password) {
                    generatedPasswordTextSpan.textContent = data.password;
                } else {
                    generatedPasswordTextSpan.textContent = 'Error!';
                    throw new Error(data.error || 'Unknown generation error');
                }
            } catch (error) {
                console.error('Generate Password Error:', error);
                alert('Error generating password: ' + error.message);
                 generatedPasswordTextSpan.textContent = 'Error generating...';
            } finally {
                 this.innerHTML = '<i class="bi bi-stars"></i> Generate Now';
                 this.disabled = false;
            }
        });
    }

    // --- Copy Generated Password Button ---
    document.querySelectorAll('.copy-generated-btn').forEach(button => {
         button.addEventListener('click', function() {
             if (!navigator.clipboard) { alert('Clipboard API not available/permitted.'); return; }
             const passwordText = generatedPasswordTextSpan ? generatedPasswordTextSpan.textContent : null;
             if (passwordText && passwordText !== 'Generate a password...' && passwordText !== 'Error generating...') {
                 navigator.clipboard.writeText(passwordText).then(() => {
                     // Simple visual feedback (optional)
                     const originalIcon = this.innerHTML;
                     this.innerHTML = '<i class="bi bi-check-lg"></i>';
                     setTimeout(() => { this.innerHTML = originalIcon; }, 1500);
                 }).catch(err => {
                     console.error('Failed to copy generated password:', err);
                     alert('Failed to copy password.');
                 });
             } else {
                 alert('No password generated yet or error occurred.');
             }
         });
    });


    // --- Show/Hide Password in Add/Edit Modal (Example, if needed later) ---
    // This targets a specific modal button if you add one
    const showHideModalButton = document.getElementById('modal-show-hide-btn'); // Example ID
    if (showHideModalButton) {
        showHideModalButton.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target'); // e.g., 'modal_entry_password'
            const passwordInput = document.getElementById(targetId);
            const icon = this.querySelector('i');
            if (passwordInput && icon) {
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    icon.classList.remove('bi-eye-fill'); icon.classList.add('bi-eye-slash-fill');
                    this.title = 'Hide Password';
                } else {
                    passwordInput.type = 'password';
                    icon.classList.remove('bi-eye-slash-fill'); icon.classList.add('bi-eye-fill');
                     this.title = 'Show Password';
                }
            }
        });
    }

    // --- Show/Hide Stored Password in Vault Cards ---
    document.querySelectorAll('.password-card .show-stored-btn').forEach(button => {
        button.addEventListener('click', async function() {
            const entryId = this.getAttribute('data-id');
            const dotsSpan = document.getElementById(`dots-${entryId}`);
            const textSpan = document.getElementById(`text-${entryId}`);
            const icon = this.querySelector('i');

            if (!dotsSpan || !textSpan || !icon) return;

            if (textSpan.style.display !== 'none') { // Hide
                textSpan.style.display = 'none'; textSpan.textContent = ''; // Clear fetched pass on hide
                dotsSpan.style.display = 'inline';
                icon.classList.remove('bi-eye-slash-fill'); icon.classList.add('bi-eye-fill');
                this.title = 'Show Password';
            } else { // Show
                if (!textSpan.textContent) { // Fetch only if not already fetched
                     this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
                     this.disabled = true;
                     try {
                        const response = await fetch(`/get_password/${entryId}`);
                        if (!response.ok) {
                            const errorData = await response.json().catch(()=>({error: `HTTP ${response.status}`}));
                            throw new Error(errorData.error || 'Failed to fetch');
                        }
                        const data = await response.json();
                        if (data.password !== undefined) textSpan.textContent = data.password || '(empty)';
                        else throw new Error(data.error || 'No password data');
                    } catch (error) {
                         console.error('Show Stored Error:', error); alert('Error: ' + error.message);
                         this.innerHTML = '<i class="bi bi-eye-fill"></i>'; this.disabled = false; return;
                     } finally { this.disabled = false; }
                }
                // Show text, hide dots
                textSpan.style.display = 'inline'; dotsSpan.style.display = 'none';
                icon.classList.remove('bi-eye-fill'); icon.classList.add('bi-eye-slash-fill');
                this.title = 'Hide Password';
                // Restore icon if loading indicator was shown
                 if (!this.querySelector('i')) this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>';
            }
        });
    });

    // --- Copy Stored Password from Vault Cards ---
    document.querySelectorAll('.password-card .copy-btn').forEach(button => {
        button.addEventListener('click', async function() {
            if (!navigator.clipboard) { alert('Clipboard API not available/permitted.'); return; }
            const entryId = this.getAttribute('data-id');
            const icon = this.querySelector('i');
            const originalIconClass = icon ? icon.className : 'bi bi-clipboard';
            if (icon) icon.className = 'spinner-border spinner-border-sm';
            this.disabled = true;

            try {
                const response = await fetch(`/get_password/${entryId}`);
                if (!response.ok) {
                    const errorData = await response.json().catch(()=>({error: `HTTP ${response.status}`}));
                    throw new Error(errorData.error || 'Failed to fetch');
                }
                const data = await response.json();
                if (data.password !== undefined) {
                    await navigator.clipboard.writeText(data.password);
                    if (icon) icon.className = 'bi bi-check-lg'; // Success
                    setTimeout(() => { if (icon) icon.className = originalIconClass; this.disabled = false; }, 2000);
                } else { throw new Error(data.error || 'No password data'); }
            } catch (error) {
                console.error("Copy error:", error); alert("Failed to copy: " + error.message);
                if (icon) icon.className = originalIconClass; // Revert icon on error
                this.disabled = false;
            }
        });
    });

     // --- Basic Flash Message Hiding ---
     // Note: This uses the simpler style from logged_in_base.html's inline script
     // If using the notification style from quantum.css, more complex JS is needed
     document.querySelectorAll('.flash-message.show').forEach(function(flash) {
         if (!flash.closest('.public-card')) { // Don't auto-hide on public pages where flash might be important
             setTimeout(function() {
                 let bsAlert = bootstrap.Alert.getInstance(flash.closest('.alert')); // If using BS alerts
                 if (bsAlert) {
                     bsAlert.close();
                 } else { // Fallback for custom flash
                    flash.style.opacity = '0';
                    // Add further transition logic if needed
                    setTimeout(function() { flash.remove(); }, 500);
                 }
             }, 5000); // Hide after 5 seconds
         }
     });

}); // End DOMContentLoaded