// static/js/vault-v3.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V3 JS Loaded - Final Version");

    // --- API Fetch Helper ---
    async function fetchApi(url, options = {}) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                // Try to parse JSON error, otherwise use status text
                let errorMsg = `Request failed with status ${response.status}`;
                try {
                    const errorData = await response.json();
                    errorMsg = errorData.error || errorMsg;
                } catch (parseError) { /* Ignore if response wasn't JSON */ }
                throw new Error(errorMsg);
            }
            // Handle potentially empty successful responses before parsing JSON
            const text = await response.text();
            return text ? JSON.parse(text) : {};
        } catch (error) {
            console.error(`API Fetch Error (${url}):`, error);
            // Optionally show a user-friendly message via alert or a dedicated UI element
            // alert(`API Error: ${error.message}`); // Simple alert for now
            throw error; // Re-throw for specific handling in calling function
        }
    }

    // --- Sidebar Add Entry Toggle ---
    // Define these globally within the DOMContentLoaded scope so they are accessible
    const addEntrySidebarBtn = document.getElementById('add-entry-sidebar-btn');
    const addEntrySection = document.getElementById('add-entry-section');

    if (addEntrySidebarBtn && addEntrySection) {
        addEntrySidebarBtn.addEventListener('click', function(event) {
            event.preventDefault(); // Prevent default link behavior
            console.log("Sidebar Add Entry Clicked!"); // Debug

            // Toggle visibility of the form section using the 'hidden' class
            const isHidden = addEntrySection.classList.contains('hidden');

            if (isHidden) {
                addEntrySection.classList.remove('hidden');
                this.classList.add('active'); // Highlight sidebar item
                // Optional: Scroll to the form
                 setTimeout(() => { // Delay scroll slightly
                    const section = document.getElementById('add-entry-section'); // Re-check element
                    if (section) {
                        section.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }
                 }, 50);
            } else {
                addEntrySection.classList.add('hidden');
                this.classList.remove('active'); // Remove highlight
                 // Also reset form if user hides it via sidebar click
                 const form = addEntrySection.querySelector('form');
                 if(form) form.reset();
            }
        });
        // console.log("Sidebar Add Entry listener attached."); // Debug
    } else {
        // Log errors if essential elements for sidebar toggle are missing
        if (!addEntrySidebarBtn) console.error("JS Error: Sidebar button #add-entry-sidebar-btn not found.");
        if (!addEntrySection) console.error("JS Error: Add entry section #add-entry-section not found.");
    }

    // --- Add Entry Form Interactions ---
    const addEntryForm = document.getElementById('add-entry-form');
    if (addEntryForm) {
        const generateBtnAdd = addEntryForm.querySelector('#generate-add-btn');
        const passwordFieldAdd = addEntryForm.querySelector('#add_entry_password');
        const showHideBtnAdd = addEntryForm.querySelector('#show-hide-add-btn');
        const cancelBtnAdd = addEntryForm.querySelector('#cancel-add-entry'); // Button specific to this form

        // Generate Password Button (Add Form)
        if (generateBtnAdd && passwordFieldAdd) {
            // console.log("Attaching listener to ADD form generate button"); // Debug
            generateBtnAdd.addEventListener('click', async function() {
                // console.log("ADD form generate button clicked"); // Debug
                const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true;
                try {
                    const data = await fetchApi('/generate_password');
                    if (data.password) {
                        passwordFieldAdd.value = data.password; passwordFieldAdd.type = 'text';
                        if(showHideBtnAdd) { const icon = showHideBtnAdd.querySelector('i'); if(icon) icon.className = 'bi bi-eye-slash-fill'; showHideBtnAdd.title = 'Hide Password'; }
                    } else { throw new Error(data.error || 'API did not return a password'); }
                } catch (error) { alert('Error generating password: ' + error.message); }
                finally { this.innerHTML = '<i class="bi bi-stars"></i>'; this.disabled = false; }
            });
        } else { /* Error Logging */ }

        // Show/Hide Password Button (Add Form)
        if (showHideBtnAdd && passwordFieldAdd) {
            showHideBtnAdd.addEventListener('click', function() {
                 const icon = this.querySelector('i'); if(!passwordFieldAdd || !icon) return;
                 if (passwordFieldAdd.type === 'password') { passwordFieldAdd.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; }
                 else { passwordFieldAdd.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
            });
         }

        // Cancel Button (Add Form)
        if (cancelBtnAdd) { // Check only if cancel button itself exists
             // console.log("Attaching listener to ADD form cancel button"); // Debug
             cancelBtnAdd.addEventListener('click', function() {
                // console.log("Add form cancel button clicked"); // Debug

                // Use variables defined in the higher scope
                if (addEntrySection) { // Check if section element exists
                    addEntrySection.classList.add('hidden'); // Hide the form SECTION
                } else { console.error("Cancel Error: Cannot find #add-entry-section to hide."); }

                if (addEntrySidebarBtn) { // Check if sidebar button element exists
                    addEntrySidebarBtn.classList.remove('active'); // Deactivate sidebar button
                } else { console.error("Cancel Error: Cannot find #add-entry-sidebar-btn to deactivate."); }

                const form = addEntryForm; // Use the form element from this scope
                if(form) form.reset(); // Reset form fields
            });
        } else { console.error("JS Error: Add form Cancel button #cancel-add-entry not found"); }

    } else { console.error("JS Error: Add Entry Form #add-entry-form not found"); }


    // --- Edit Entry Modal & its Buttons ---
    const editEntryModalElement = document.getElementById('entryModal');
    let editEntryModalInstance = null;
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

                editForm.reset(); editModalTitle.textContent = 'Loading Entry...';
                editModalSubmitBtn.textContent = 'Update Entry'; editModalSubmitBtn.className = 'btn btn-primary';
                editPasswordInput.required = false; editEntryIdInput.value = entryId;
                editForm.action = `/update_entry/${entryId}`;
                if(editModalHelpText) editModalHelpText.style.display = 'block';

                try {
                    const data = await fetchApi(`/get_entry_details/${entryId}`);
                    editLaptopServerInput.value = data.laptop_server || '';
                    editBrandLabelInput.value = data.brand_label || '';
                    editUsernameInput.value = data.entry_username || '';
                    editPasswordInput.value = data.password || '';
                    editPasswordInput.placeholder = "Leave blank to keep current password";
                    editPasswordInput.type = 'password';
                    if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-fill'; showHideEditModalBtn.title = 'Show Password';}
                    editModalTitle.textContent = `Edit: ${data.laptop_server || 'Entry'}`;
                } catch (error) {
                    alert(`Failed to load entry details: ${error.message}`);
                    editModalTitle.textContent = 'Edit Vault Entry';
                    if(editEntryModalInstance) editEntryModalInstance.hide();
                }
            });
        });

         // Reset modal state when hidden
         editEntryModalElement.addEventListener('hidden.bs.modal', function (event) {
             editForm.reset(); editModalTitle.textContent = 'Edit Vault Entry';
             editPasswordInput.required = false; editForm.action = '#';
             if(editModalHelpText) editModalHelpText.style.display = 'none';
         });

         // Generate Button inside Edit Modal
         if (generateEditModalBtn && editPasswordInput) {
            // console.log("Attaching listener to EDIT modal generate button");
            generateEditModalBtn.addEventListener('click', async function() {
                 // console.log("EDIT modal generate button clicked");
                 const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true;
                 try {
                     const data = await fetchApi('/generate_password');
                     if (data.password) {
                        editPasswordInput.value = data.password; editPasswordInput.type = 'text';
                        if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-slash-fill'; showHideEditModalBtn.title = 'Hide Password'; }
                     } else { throw new Error(data.error || 'API did not return password'); }
                 } catch (error) { alert('Error generating password: ' + error.message); }
                 finally { this.innerHTML = '<i class="bi bi-stars"></i>'; this.disabled = false; }
             });
         } else { /* Error Logging */ }

         // Show/Hide Button inside Edit Modal
         if (showHideEditModalBtn && editPasswordInput) {
              showHideEditModalBtn.addEventListener('click', function() {
                 const icon = this.querySelector('i'); if(!editPasswordInput || !icon) return;
                 if (editPasswordInput.type === 'password') { editPasswordInput.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; }
                 else { editPasswordInput.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
             });
         } else { /* Error Logging */ }

    } // End if(editEntryModalElement)

    // --- Show/Hide Stored Password in Vault Cards ---
    document.querySelectorAll('.entry-card .show-stored-btn').forEach(button => {
         button.addEventListener('click', async function(event) {
             event.stopPropagation(); const card = this.closest('.entry-card'); if (!card) return;
             const entryId = this.getAttribute('data-id'); const dotsSpan = card.querySelector('.password-mask');
             const textSpan = card.querySelector('.password-revealed'); const icon = this.querySelector('i');
             if (!dotsSpan || !textSpan || !icon) return;
             if (textSpan.style.display !== 'none') { /* Hide */ textSpan.style.display = 'none'; textSpan.textContent = ''; dotsSpan.style.display = 'inline-block'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
             else { /* Show */ if (!textSpan.textContent) { this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true;
                     try { const data = await fetchApi(`/get_password/${entryId}`); textSpan.textContent = data.password || '(empty)'; }
                     catch (error) { alert('Error: ' + error.message); this.innerHTML = '<i class="bi bi-eye-fill"></i>'; this.disabled = false; return; }
                     finally { this.disabled = false; } }
                 textSpan.style.display = 'inline-block'; dotsSpan.style.display = 'none'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password';
                 if (!this.querySelector('i')) this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>'; }
         });
    });

    // --- Copy Stored Password from Vault Cards ---
    document.querySelectorAll('.entry-card .copy-btn').forEach(button => {
         button.addEventListener('click', async function(event) {
             event.stopPropagation(); if (!navigator.clipboard) { alert('Clipboard API not permitted.'); return; }
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