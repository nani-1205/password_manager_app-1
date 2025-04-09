// static/js/vault-v3.js
document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V3 JS Loaded");

    // --- API Fetch Helper ---
    async function fetchApi(url, options = {}) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: `HTTP Error ${response.status}` }));
                throw new Error(errorData.error || `Request failed with status ${response.status}`);
            }
            const text = await response.text();
            return text ? JSON.parse(text) : {};
        } catch (error) { console.error(`API Fetch Error (${url}):`, error); throw error; }
    }

    // --- Sidebar Add Entry Toggle (Now opens Modal) ---
    const addEntrySidebarBtn = document.getElementById('add-entry-sidebar-btn'); // Make sure this ID exists on the sidebar item
    const entryModalElement = document.getElementById('entryModal');
    let entryModal = null;
    if (entryModalElement) {
        entryModal = new bootstrap.Modal(entryModalElement); // Initialize Bootstrap Modal
        const entryModalForm = document.getElementById('entry-modal-form');
        const entryModalLabel = document.getElementById('entryModalLabel');
        const entryModalSubmitBtn = document.getElementById('modal_submit_button');
        const entryModalPasswordField = document.getElementById('modal_entry_password');
        const entryModalIdField = document.getElementById('modal_entry_id');

        if (addEntrySidebarBtn && entryModalForm && entryModalLabel && entryModalSubmitBtn && entryModalPasswordField) {
            addEntrySidebarBtn.addEventListener('click', function(event) {
                event.preventDefault();
                entryModalForm.reset(); // Clear form
                entryModalLabel.textContent = 'Add New Vault Entry'; // Set title for Add
                entryModalForm.action = '/add_entry'; // Set action for Add
                entryModalSubmitBtn.textContent = 'Save Entry';
                entryModalSubmitBtn.className = 'btn btn-success'; // Style as Save
                entryModalPasswordField.required = true; // Password required for Add
                entryModalIdField.value = ''; // Clear hidden ID field
                document.getElementById('modalPasswordHelp').style.display = 'none'; // Hide edit help text
                entryModal.show(); // Show the modal
                addEntrySidebarBtn.classList.add('active'); // Keep sidebar active while modal open
            });
        }

        // Remove active class from sidebar when modal hides
        entryModalElement.addEventListener('hidden.bs.modal', event => {
             if(addEntrySidebarBtn) addEntrySidebarBtn.classList.remove('active');
        });

        // Add/Edit Modal - Generate Password Button
        const generateModalBtn = document.getElementById('generate-modal-btn');
        if (generateModalBtn && entryModalPasswordField) {
            generateModalBtn.addEventListener('click', async function() {
                const originalHtml = this.innerHTML;
                this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>'; this.disabled = true;
                try {
                    const data = await fetchApi('/generate_password');
                    entryModalPasswordField.value = data.password;
                    entryModalPasswordField.type = 'text'; // Show generated pass
                    // Update show/hide button state
                    const showHideBtn = document.getElementById('show-hide-modal-btn');
                    if(showHideBtn) {
                        const icon = showHideBtn.querySelector('i');
                        if(icon) icon.className = 'bi bi-eye-slash-fill';
                        showHideBtn.title = 'Hide Password';
                    }
                } catch (error) { alert('Error generating password: ' + error.message); }
                finally { this.innerHTML = originalHtml; this.disabled = false; }
            });
        }

        // Add/Edit Modal - Show/Hide Password Button
        const showHideModalBtn = document.getElementById('show-hide-modal-btn');
        if (showHideModalBtn && entryModalPasswordField) {
             showHideModalBtn.addEventListener('click', function() {
                const icon = this.querySelector('i');
                if(entryModalPasswordField && icon) {
                    if (entryModalPasswordField.type === 'password') { entryModalPasswordField.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; }
                    else { entryModalPasswordField.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
                }
             });
         }

        // --- Logic to Populate Edit Modal ---
        document.querySelectorAll('.entry-card .edit-btn').forEach(button => {
            button.addEventListener('click', async function(event) {
                event.stopPropagation(); // Prevent card click if needed
                const entryId = this.getAttribute('data-id');
                if (!entryId) return;

                // Reset and Prepare Modal for Editing
                entryModalForm.reset();
                entryModalLabel.textContent = 'Loading Entry...';
                entryModalSubmitBtn.textContent = 'Update Entry';
                entryModalSubmitBtn.className = 'btn btn-primary'; // Style as Update
                entryModalPasswordField.required = false; // Password NOT required for Edit
                entryModalIdField.value = entryId; // Set hidden ID for reference maybe
                entryModalForm.action = `/update_entry/${entryId}`; // Set specific update action URL
                document.getElementById('modalPasswordHelp').style.display = 'block'; // Show edit help text

                try {
                    const data = await fetchApi(`/get_entry_details/${entryId}`); // Fetch details
                    // Populate form
                    document.getElementById('modal_laptop_server').value = data.laptop_server || '';
                    document.getElementById('modal_brand_label').value = data.brand_label || '';
                    document.getElementById('modal_entry_username').value = data.entry_username || '';
                    entryModalPasswordField.value = data.password || ''; // Pre-fill decrypted password
                    entryModalPasswordField.type = 'password'; // Ensure it starts hidden
                    // Reset show/hide button state
                    if(showHideModalBtn) {
                        const icon = showHideModalBtn.querySelector('i');
                        if(icon) icon.className = 'bi bi-eye-fill';
                        showHideModalBtn.title = 'Show Password';
                    }
                    entryModalLabel.textContent = `Edit Entry: ${data.laptop_server || '...'}`;
                    // entryModal.show(); // Modal is shown automatically by data-bs-toggle

                } catch (error) {
                    alert(`Failed to load entry details: ${error.message}`);
                    entryModalLabel.textContent = 'Edit Vault Entry'; // Reset title on error
                    entryModal.hide(); // Hide modal if fetch failed
                }
            });
        });

    } // End if(entryModalElement)


    // --- Show/Hide Stored Password in Vault Cards ---
    document.querySelectorAll('.entry-card .show-stored-btn').forEach(button => {
        button.addEventListener('click', async function(event) {
            event.stopPropagation();
            const card = this.closest('.entry-card'); if (!card) return;
            const entryId = this.getAttribute('data-id');
            const dotsSpan = card.querySelector('.password-mask');
            const textSpan = card.querySelector('.password-revealed');
            const icon = this.querySelector('i');
            if (!dotsSpan || !textSpan || !icon) return;

            if (textSpan.style.display !== 'none') { // Hide
                textSpan.style.display = 'none'; textSpan.textContent = ''; // Clear password on hide
                dotsSpan.style.display = 'inline-block';
                icon.className = 'bi bi-eye-fill'; this.title = 'Show Password';
            } else { // Show
                if (!textSpan.textContent) { // Fetch only if not already loaded
                     this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>'; this.disabled = true;
                     try {
                        const data = await fetchApi(`/get_password/${entryId}`);
                        textSpan.textContent = data.password || '(empty)';
                    } catch (error) { alert('Error fetching password: ' + error.message); this.innerHTML = '<i class="bi bi-eye-fill"></i>'; this.disabled = false; return; }
                     finally { this.disabled = false; }
                }
                textSpan.style.display = 'inline-block'; dotsSpan.style.display = 'none';
                icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password';
                if (!this.querySelector('i')) this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>'; // Restore icon if spinner was used
            }
        });
    });

    // --- Copy Stored Password from Vault Cards ---
    document.querySelectorAll('.entry-card .copy-btn').forEach(button => {
        button.addEventListener('click', async function(event) {
            event.stopPropagation();
            if (!navigator.clipboard) { alert('Clipboard API not available/permitted.'); return; }
            const entryId = this.getAttribute('data-id');
            const icon = this.querySelector('i');
            const originalIconClass = icon ? icon.className : 'bi bi-clipboard-fill';
            if (icon) icon.className = 'spinner-border spinner-border-sm text-primary';
            this.disabled = true; this.title = 'Copying...';

            try {
                const data = await fetchApi(`/get_password/${entryId}`);
                await navigator.clipboard.writeText(data.password);
                if (icon) icon.className = 'bi bi-check-lg text-success';
                this.title = 'Copied!';
                setTimeout(() => { if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }, 1500);
            } catch (error) {
                console.error("Copy error:", error); alert("Failed to copy: " + error.message);
                if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password';
            }
        });
    });

}); // End DOMContentLoaded