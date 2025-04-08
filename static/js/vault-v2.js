// static/js/vault-v2.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V2 JS Loaded");

    const showFlashMessage = (message, type = 'info') => {
        // Basic JS flash implementation (can be improved)
        const container = document.querySelector('.container > main'); // Adjust selector if needed
        if (!container) return;

        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.setAttribute('role', 'alert');
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        // Prepend to main content area
        container.insertBefore(alertDiv, container.firstChild);

        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            let bsAlert = bootstrap.Alert.getInstance(alertDiv);
            if (bsAlert) {
                bsAlert.close();
            } else {
                alertDiv.remove(); // Fallback remove
            }
        }, 5000);
    };


    // --- API Fetch Helper ---
    async function fetchApi(url, options = {}) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: `HTTP Error ${response.status}` }));
                throw new Error(errorData.error || `Request failed with status ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`API Fetch Error (${url}):`, error);
            throw error; // Re-throw for specific handling
        }
    }

    // --- Password Generation in Modal (if Add Entry Modal Exists) ---
    const addEntryModal = document.getElementById('addEntryModal');
    if (addEntryModal) {
        const generateModalBtn = addEntryModal.querySelector('.generate-modal-password'); // Add this class/ID to modal button if needed
        const passwordModalField = addEntryModal.querySelector('#modal_entry_password');
        if (generateModalBtn && passwordModalField) {
            generateModalBtn.addEventListener('click', async () => {
                 generateModalBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
                 generateModalBtn.disabled = true;
                 try {
                     const data = await fetchApi('/generate_password');
                     passwordModalField.value = data.password;
                 } catch (error) {
                     showFlashMessage('Error generating password: ' + error.message, 'danger');
                 } finally {
                     generateModalBtn.innerHTML = '<i class="bi bi-stars"></i>'; // Restore icon
                     generateModalBtn.disabled = false;
                 }
            });
        }
        // Add Show/Hide for modal password field if desired
    }


    // --- Show/Hide Stored Password in Vault Cards ---
    document.querySelectorAll('.entry-card .show-stored-btn').forEach(button => {
        button.addEventListener('click', async function() {
            const card = this.closest('.entry-card');
            if (!card) return;

            const entryId = this.getAttribute('data-id');
            const dotsSpan = card.querySelector('.password-mask');
            const textSpan = card.querySelector('.password-revealed');
            const icon = this.querySelector('i');

            if (!dotsSpan || !textSpan || !icon) return;

            if (textSpan.style.display !== 'none') { // Hide
                textSpan.style.display = 'none'; textSpan.textContent = '';
                dotsSpan.style.display = 'inline-block'; // Use inline-block or block based on CSS needs
                icon.className = 'bi bi-eye-fill'; // Show eye icon
                this.title = 'Show Password';
            } else { // Show
                if (!textSpan.textContent) { // Fetch only once
                     this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
                     this.disabled = true;
                     try {
                        const data = await fetchApi(`/get_password/${entryId}`);
                        textSpan.textContent = data.password || '(empty)';
                    } catch (error) {
                         showFlashMessage('Error fetching password: ' + error.message, 'danger');
                         this.innerHTML = '<i class="bi bi-eye-fill"></i>'; this.disabled = false; return;
                     } finally { this.disabled = false; }
                }
                textSpan.style.display = 'inline-block'; dotsSpan.style.display = 'none';
                icon.className = 'bi bi-eye-slash-fill'; // Show slashed eye icon
                this.title = 'Hide Password';
                // Restore icon if needed
                 if (!this.querySelector('i')) this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>';
            }
        });
    });

    // --- Copy Stored Password from Vault Cards ---
    document.querySelectorAll('.entry-card .copy-btn').forEach(button => {
        button.addEventListener('click', async function() {
            if (!navigator.clipboard) { showFlashMessage('Clipboard API not available/permitted.', 'warning'); return; }
            const entryId = this.getAttribute('data-id');
            const icon = this.querySelector('i');
            const originalIconClass = icon ? icon.className : 'bi bi-clipboard';
            if (icon) icon.className = 'spinner-border spinner-border-sm text-primary'; // Use spinner class
            this.disabled = true;

            try {
                const data = await fetchApi(`/get_password/${entryId}`);
                await navigator.clipboard.writeText(data.password);
                if (icon) icon.className = 'bi bi-check-lg text-success'; // Success icon
                showFlashMessage('Password copied to clipboard!', 'success');
                setTimeout(() => { if (icon) icon.className = originalIconClass; this.disabled = false; }, 2000); // Revert after 2s
            } catch (error) {
                showFlashMessage('Failed to copy: ' + error.message, 'danger');
                if (icon) icon.className = originalIconClass; // Revert icon on error
                this.disabled = false;
            }
        });
    });

}); // End DOMContentLoaded