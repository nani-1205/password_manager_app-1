// static/js/vault-v2.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V2 JS Loaded - Refined");

    // --- Flash Message Helper (Optional - using Bootstrap default dismissal now) ---
    // const showFlashMessage = (message, type = 'info') => { ... } // Removed for now

    // --- API Fetch Helper ---
    async function fetchApi(url, options = {}) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: `HTTP Error ${response.status}` }));
                throw new Error(errorData.error || `Request failed with status ${response.status}`);
            }
            // Check for empty response body before parsing JSON
            const text = await response.text();
            return text ? JSON.parse(text) : {}; // Return empty object for empty response
        } catch (error) {
            console.error(`API Fetch Error (${url}):`, error);
            throw error; // Re-throw for specific handling
        }
    }

    // --- Add Entry Modal ---
    const addEntryModalElement = document.getElementById('addEntryModal');
    let addEntryModal = null;
    if (addEntryModalElement) {
        addEntryModal = new bootstrap.Modal(addEntryModalElement); // Initialize Bootstrap Modal

        // Optional: Clear form when modal is hidden
        addEntryModalElement.addEventListener('hidden.bs.modal', event => {
            const form = addEntryModalElement.querySelector('form');
            if (form) form.reset();
        });

        // Add Password Generation inside Modal
        const generateModalBtn = addEntryModalElement.querySelector('.generate-modal-password'); // Use this class if you add the button
        const passwordModalField = addEntryModalElement.querySelector('#modal_entry_password');
        if (generateModalBtn && passwordModalField) {
            generateModalBtn.addEventListener('click', async () => {
                // ... (Password generation logic as before, targeting modal field) ...
            });
        }
    }

    // --- Show/Hide Stored Password in Vault Cards ---
    document.querySelectorAll('.entry-card .show-stored-btn').forEach(button => {
        button.addEventListener('click', async function(event) {
            event.stopPropagation(); // Prevent card click if button is clicked
            const card = this.closest('.entry-card');
            if (!card) return;

            const entryId = this.getAttribute('data-id');
            const dotsSpan = card.querySelector('.password-mask');
            const textSpan = card.querySelector('.password-revealed');
            const icon = this.querySelector('i');

            if (!dotsSpan || !textSpan || !icon) return;

            if (textSpan.style.display !== 'none') { // Hide
                textSpan.style.display = 'none'; textSpan.textContent = '';
                dotsSpan.style.display = 'inline-block';
                icon.className = 'bi bi-eye-fill';
                this.title = 'Show Password';
            } else { // Show
                // Prevent multiple fetches if already shown then hidden
                if (!textSpan.textContent) {
                     this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
                     this.disabled = true;
                     try {
                        const data = await fetchApi(`/get_password/${entryId}`);
                        textSpan.textContent = data.password || '(empty)';
                    } catch (error) {
                         alert('Error fetching password: ' + error.message); // Use alert as flash isn't ideal here
                         this.innerHTML = '<i class="bi bi-eye-fill"></i>'; this.disabled = false; return;
                     } finally { this.disabled = false; }
                }
                textSpan.style.display = 'inline-block'; dotsSpan.style.display = 'none';
                icon.className = 'bi bi-eye-slash-fill';
                this.title = 'Hide Password';
                 // Restore icon if needed
                 if (!this.querySelector('i')) this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>';
            }
        });
    });

    // --- Copy Stored Password from Vault Cards ---
    document.querySelectorAll('.entry-card .copy-btn').forEach(button => {
        button.addEventListener('click', async function(event) {
            event.stopPropagation(); // Prevent card click
            if (!navigator.clipboard) { alert('Clipboard API not available/permitted.'); return; }
            const entryId = this.getAttribute('data-id');
            const icon = this.querySelector('i');
            const originalIconClass = icon ? icon.className : 'bi bi-clipboard-fill'; // Default icon

            // Indicate loading
            if (icon) icon.className = 'spinner-border spinner-border-sm';
            this.disabled = true;
            this.title = 'Copying...';

            try {
                const data = await fetchApi(`/get_password/${entryId}`);
                await navigator.clipboard.writeText(data.password);

                // Provide visual feedback
                if (icon) icon.className = 'bi bi-check-lg text-success'; // Success icon
                this.title = 'Copied!';

                // Revert after a delay
                setTimeout(() => {
                    if (icon) icon.className = originalIconClass;
                    this.disabled = false;
                    this.title = 'Copy Password';
                }, 1500); // Revert after 1.5 seconds

            } catch (error) {
                console.error("Copy error:", error);
                alert("Failed to copy: " + error.message);
                if (icon) icon.className = originalIconClass; // Revert icon on error
                this.disabled = false;
                this.title = 'Copy Password';
            }
        });
    });

}); // End DOMContentLoaded