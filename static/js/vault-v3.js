// static/js/vault-v3.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V3 JS Loaded - Sidebar Toggle Added"); // Log specific load point

    // --- Sidebar Add Entry Toggle ---
    const addEntrySidebarBtn = document.getElementById('add-entry-sidebar-btn'); // ID on the sidebar <a> tag
    const addEntrySection = document.getElementById('add-entry-section'); // ID on the form container div in quantum_vault_v3.html

    // --- DEBUG ---
    // console.log("Sidebar Button Element:", addEntrySidebarBtn);
    // console.log("Add Entry Section Element:", addEntrySection);
    // --- END DEBUG ---

    if (addEntrySidebarBtn && addEntrySection) {
        addEntrySidebarBtn.addEventListener('click', function(event) {
            event.preventDefault(); // MUST prevent default anchor tag behavior
            // console.log("Add Entry Sidebar Button Clicked!"); // --- DEBUG ---

            // Toggle visibility of the form section using the 'hidden' class
            const isHidden = addEntrySection.classList.contains('hidden');
            // console.log("Is section currently hidden?", isHidden); // --- DEBUG ---

            if (isHidden) {
                addEntrySection.classList.remove('hidden');
                this.classList.add('active'); // Highlight sidebar item
                // console.log("Showing add entry section."); // --- DEBUG ---
                // Optional: Scroll to the form
                setTimeout(() => { // Delay scroll slightly after display change
                    addEntrySection.scrollIntoView({ behavior: 'smooth', block: 'start' }); // scroll to start
                 }, 50);
            } else {
                addEntrySection.classList.add('hidden');
                this.classList.remove('active'); // Remove highlight
                // console.log("Hiding add entry section."); // --- DEBUG ---
            }
        });
        // console.log("Add Entry Sidebar click listener attached."); // --- DEBUG ---
    } else {
        if (!addEntrySidebarBtn) console.error("JS Error: Could not find sidebar button with ID: add-entry-sidebar-btn");
        if (!addEntrySection) console.error("JS Error: Could not find add entry section with ID: add-entry-section");
    }

    // --- API Fetch Helper ---
    async function fetchApi(url, options = {}) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: `HTTP Error ${response.status}` }));
                throw new Error(errorData.error || `Request failed with status ${response.status}`);
            }
            const text = await response.text();
            return text ? JSON.parse(text) : {}; // Handle potentially empty JSON responses
        } catch (error) {
            console.error(`API Fetch Error (${url}):`, error);
            // Optionally show a generic error message to the user here
            // showFlashMessage(`API Error: ${error.message}`, 'danger');
            throw error; // Re-throw for specific handling in calling function
        }
    }

    // --- Add Entry Form Buttons (Generate/Show/Hide/Cancel) ---
    const addEntryForm = document.getElementById('add-entry-form');
    if (addEntryForm) {
        const generateBtn = addEntryForm.querySelector('#generate-btn');
        const passwordField = addEntryForm.querySelector('#entry_password');
        const showHideBtn = addEntryForm.querySelector('#show-hide-btn');
        const cancelBtn = addEntryForm.querySelector('#cancel-add-entry'); // Get cancel button for this form

        // Generate Password Button
        if (generateBtn && passwordField) {
            generateBtn.addEventListener('click', async function() {
                const originalHtml = this.innerHTML;
                this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>'; this.disabled = true;
                try {
                    const data = await fetchApi('/generate_password');
                    passwordField.value = data.password;
                    passwordField.type = 'text'; // Show generated pass
                    if(showHideBtn) { // Update show/hide button state
                        const icon = showHideBtn.querySelector('i');
                        if(icon) icon.className = 'bi bi-eye-slash-fill';
                        showHideBtn.title = 'Hide Password';
                    }
                } catch (error) { alert('Error generating password: ' + error.message); }
                finally { this.innerHTML = originalHtml; this.disabled = false; }
            });
        }

        // Show/Hide Password Button
        if (showHideBtn && passwordField) {
            showHideBtn.addEventListener('click', function() {
                 const icon = this.querySelector('i');
                 if(passwordField && icon) {
                    if (passwordField.type === 'password') {
                        passwordField.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password';
                    } else {
                        passwordField.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password';
                    }
                 }
            });
         }

        // Cancel Button for Add Form (logic moved from inline script)
        if (cancelBtn && addSection && addSidebarBtn) {
            cancelBtn.addEventListener('click', function() {
                addSection.classList.add('hidden'); addSidebarBtn.classList.remove('active');
                const form = addSection.querySelector('form'); if(form) form.reset();
            });
        }

    } // end if(addEntryForm)


    // --- Edit Entry Modal & its Buttons ---
    const editEntryModalElement = document.getElementById('entryModal'); // Shared Modal ID
    let editEntryModalInstance = null; // Bootstrap Modal instance
    if (editEntryModalElement) {
        editEntryModalInstance = new bootstrap.Modal(editEntryModalElement);
        const editForm = document.getElementById('entry-modal-form');
        const editEntryIdInput = document.getElementById('modal_entry_id');
        const editLaptopServerInput = document.getElementById('modal_laptop_server');
        const editBrandLabelInput = document.getElementById('modal_brand_label');
        const editUsernameInput = document.getElementById('modal_entry_username');
        const editPasswordInput = document.getElementById('modal_entry_password');
        const editModalTitle = document.getElementById('entryModalLabel');
        const editModalSubmitBtn = document.getElementById('modal_submit_button');
        const editModalHelpText = document.getElementById('modalPasswordHelp');
        const generateEditModalBtn = document.getElementById('generate-modal-btn');
        const showHideEditModalBtn = document.getElementById('show-hide-modal-btn');

        // Listener for all edit buttons on cards to trigger modal population
        document.querySelectorAll('.entry-card .edit-btn').forEach(button => {
            button.addEventListener('click', async function(event) {
                event.stopPropagation();
                const entryId = this.getAttribute('data-id'); if (!entryId) return;

                // Prepare Modal for Editing
                editForm.reset(); // Clear previous values
                editModalTitle.textContent = 'Loading Entry...';
                editModalSubmitBtn.textContent = 'Update Entry';
                editModalSubmitBtn.className = 'btn btn-primary'; // Ensure correct button style
                editPasswordInput.required = false; // Not required for update
                editEntryIdInput.value = entryId; // Store ID (useful for reference)
                editForm.action = `/update_entry/${entryId}`; // Set form submission URL
                if(editModalHelpText) editModalHelpText.style.display = 'block'; // Show help text

                try {
                    const data = await fetchApi(`/get_entry_details/${entryId}`); // Fetch ALL details
                    // Populate form fields
                    editLaptopServerInput.value = data.laptop_server || '';
                    editBrandLabelInput.value = data.brand_label || '';
                    editUsernameInput.value = data.entry_username || '';
                    editPasswordInput.value = data.password || ''; // Pre-fill DECRYPTED password
                    editPasswordInput.placeholder = "Leave blank to keep current password";
                    editPasswordInput.type = 'password'; // Start hidden

                    // Reset show/hide button state
                    if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-fill'; showHideEditModalBtn.title = 'Show Password'; }

                    editModalTitle.textContent = `Edit: ${data.laptop_server || 'Entry'}`;
                    // Modal is shown via data-bs-toggle, no need for JS show here usually

                } catch (error) {
                    alert(`Failed to load entry details: ${error.message}`); // Use alert for modal errors
                    editModalTitle.textContent = 'Edit Vault Entry'; // Reset title
                    // Manually hide if needed (might not be necessary if data-bs-toggle worked)
                    if(editEntryModalInstance) editEntryModalInstance.hide();
                }
            });
        });

         // Reset modal state when hidden (important!)
         editEntryModalElement.addEventListener('hidden.bs.modal', function (event) {
             editForm.reset();
             editModalTitle.textContent = 'Edit Vault Entry'; // Reset title
             editPasswordInput.required = false; // Default to not required
             editForm.action = '#'; // Clear action
             if(editModalHelpText) editModalHelpText.style.display = 'none'; // Hide help text
         });

         // Generate Button inside Edit Modal
         if (generateEditModalBtn && editPasswordInput) {
             generateEditModalBtn.addEventListener('click', async function() {
                 const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true;
                 try {
                     const data = await fetchApi('/generate_password');
                     editPasswordInput.value = data.password;
                     editPasswordInput.type = 'text'; // Show generated pass
                     // Update show/hide state
                     if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-slash-fill'; showHideEditModalBtn.title = 'Hide Password'; }
                 } catch (error) { alert('Error generating password: ' + error.message); }
                 finally { this.innerHTML = '<i class="bi bi-stars"></i>'; this.disabled = false; }
             });
         }

         // Show/Hide Button inside Edit Modal
         if (showHideEditModalBtn && editPasswordInput) {
              showHideEditModalBtn.addEventListener('click', function() {
                 const icon = this.querySelector('i'); if(!editPasswordInput || !icon) return;
                 if (editPasswordInput.type === 'password') { editPasswordInput.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; }
                 else { editPasswordInput.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
             });
         }

    } // End if(editEntryModalElement)


    // --- Show/Hide Stored Password in Vault Cards ---
    document.querySelectorAll('.entry-card .show-stored-btn').forEach(button => {
         button.addEventListener('click', async function(event) {
             event.stopPropagation(); const card = this.closest('.entry-card'); if (!card) return;
             const entryId = this.getAttribute('data-id'); const dotsSpan = card.querySelector('.password-mask');
             const textSpan = card.querySelector('.password-revealed'); const icon = this.querySelector('i');
             if (!dotsSpan || !textSpan || !icon) return;

             if (textSpan.style.display !== 'none') { // HIDE Action
                 textSpan.style.display = 'none'; textSpan.textContent = ''; // Clear password
                 dotsSpan.style.display = 'inline-block';
                 icon.className = 'bi bi-eye-fill'; this.title = 'Show Password';
             } else { // SHOW Action
                 if (!textSpan.textContent) { // Fetch only if needed
                     this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>'; this.disabled = true;
                     try { const data = await fetchApi(`/get_password/${entryId}`); textSpan.textContent = data.password || '(empty)'; }
                     catch (error) { alert('Error fetching password: ' + error.message); this.innerHTML = '<i class="bi bi-eye-fill"></i>'; this.disabled = false; return; }
                     finally { this.disabled = false; }
                 }
                 textSpan.style.display = 'inline-block'; dotsSpan.style.display = 'none';
                 icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password';
                 if (!this.querySelector('i')) this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>'; // Restore icon if spinner shown
             }
         });
    });

    // --- Copy Stored Password from Vault Cards ---
    document.querySelectorAll('.entry-card .copy-btn').forEach(button => {
         button.addEventListener('click', async function(event) {
             event.stopPropagation(); if (!navigator.clipboard) { alert('Clipboard API not available/permitted.'); return; }
             const entryId = this.getAttribute('data-id'); const icon = this.querySelector('i');
             const originalIconClass = icon ? icon.className : 'bi bi-clipboard-fill';
             if (icon) icon.className = 'spinner-border spinner-border-sm text-primary'; this.disabled = true; this.title = 'Copying...';

             try { const data = await fetchApi(`/get_password/${entryId}`); await navigator.clipboard.writeText(data.password);
                 if (icon) icon.className = 'bi bi-check-lg text-success'; this.title = 'Copied!';
                 setTimeout(() => { if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }, 1500);
             } catch (error) { console.error("Copy error:", error); alert("Failed to copy: " + error.message); if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }
         });
    });

}); // End DOMContentLoaded