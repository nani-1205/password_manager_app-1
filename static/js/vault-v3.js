// static/js/vault-v3.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V3 JS Loaded - Final Check with Cancel Fix");

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
            // Optionally show a user-friendly message via flash or alert
            // For simplicity in JS, console log is primary feedback here
            throw error; // Re-throw for specific handling if needed
        }
    }

    // --- Sidebar Add Entry Toggle ---
    // Define these globally within the DOMContentLoaded scope so they ARE available later if needed
    const addEntrySidebarBtn = document.getElementById('add-entry-sidebar-btn');
    const addEntrySection = document.getElementById('add-entry-section');

    if (addEntrySidebarBtn && addEntrySection) {
        addEntrySidebarBtn.addEventListener('click', function(event) {
            event.preventDefault(); // Prevent default anchor tag behavior
            console.log("Sidebar Add Entry Clicked!"); // Debug

            // Toggle visibility of the form section using the 'hidden' class
            const isHidden = addEntrySection.classList.contains('hidden');
            // console.log("Is section currently hidden?", isHidden); // Debug

            if (isHidden) {
                addEntrySection.classList.remove('hidden');
                this.classList.add('active'); // Highlight sidebar item
                // Optional: Scroll to the form
                 setTimeout(() => { // Delay scroll slightly after display change
                    // Check if the element exists before scrolling
                    const section = document.getElementById('add-entry-section');
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
        if (!addEntrySidebarBtn) console.error("JS Error: Sidebar button #add-entry-sidebar-btn not found.");
        if (!addEntrySection) console.error("JS Error: Add entry section #add-entry-section not found.");
    }

    // --- Add Entry Form Interactions ---
    const addEntryForm = document.getElementById('add-entry-form');
    if (addEntryForm) {
        const generateBtnAdd = addEntryForm.querySelector('#generate-add-btn'); // Specific ID
        const passwordFieldAdd = addEntryForm.querySelector('#add_entry_password'); // Specific ID
        const showHideBtnAdd = addEntryForm.querySelector('#show-hide-add-btn'); // Specific ID
        const cancelBtnAdd = addEntryForm.querySelector('#cancel-add-entry'); // Specific ID for Add form cancel

        // Generate Password Button (Add Form)
        if (generateBtnAdd && passwordFieldAdd) {
            // console.log("Attaching listener to ADD form generate button"); // Debug
            generateBtnAdd.addEventListener('click', async function() {
                // console.log("ADD form generate button clicked"); // Debug
                const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>'; this.disabled = true;
                try {
                    const data = await fetchApi('/generate_password');
                    if (data.password) { // Check if password exists in response
                        passwordFieldAdd.value = data.password; passwordFieldAdd.type = 'text';
                        if(showHideBtnAdd) { // Update corresponding show/hide button
                            const icon = showHideBtnAdd.querySelector('i');
                            if(icon) icon.className = 'bi bi-eye-slash-fill';
                            showHideBtnAdd.title = 'Hide Password';
                        }
                    } else { throw new Error(data.error || 'API did not return a password'); }
                } catch (error) { alert('Error generating password: ' + error.message); }
                finally { this.innerHTML = '<i class="bi bi-stars"></i>'; this.disabled = false; } // Restore icon
            });
        } else { if (!generateBtnAdd) console.error("JS Error: #generate-add-btn not found in Add Form"); if (!passwordFieldAdd) console.error("JS Error: #add_entry_password not found in Add Form"); }

        // Show/Hide Password Button (Add Form)
        if (showHideBtnAdd && passwordFieldAdd) {
            showHideBtnAdd.addEventListener('click', function() {
                 const icon = this.querySelector('i'); if(!passwordFieldAdd || !icon) return;
                 if (passwordFieldAdd.type === 'password') { passwordFieldAdd.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; }
                 else { passwordFieldAdd.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
            });
            // console.log("Add Entry Form Show/Hide listener attached."); // Debug
         }

        // --- CORRECTED Cancel Button (Add Form) Listener ---
        if (cancelBtnAdd) { // Only need to check if cancel button itself exists here
             // console.log("Attaching listener to ADD form cancel button"); // Debug
             cancelBtnAdd.addEventListener('click', function() {
                // console.log("Add form cancel button clicked"); // Debug

                // --- Re-select elements needed within this specific handler ---
                // These elements *should* exist if this listener runs, but re-selecting is safer
                const sectionToHide = document.getElementById('add-entry-section'); // Get the section again
                const sidebarButtonToDeactivate = document.getElementById('add-entry-sidebar-btn'); // Get sidebar button again
                // --- End Re-selection ---

                if (sectionToHide) {
                    sectionToHide.classList.add('hidden'); // Hide the form SECTION
                } else {
                    console.error("Cancel Error: Cannot find #add-entry-section to hide.");
                }

                if (sidebarButtonToDeactivate) {
                    sidebarButtonToDeactivate.classList.remove('active'); // Deactivate sidebar button
                } else {
                     console.error("Cancel Error: Cannot find #add-entry-sidebar-btn to deactivate.");
                }

                const form = addEntryForm; // We already have the form element from outer scope
                if(form) form.reset(); // Reset form fields
            });
        } else {
            console.error("JS Error: Add form Cancel button #cancel-add-entry not found");
        }
        // --- END CORRECTION ---

    } else { console.error("JS Error: Add Entry Form #add-entry-form not found"); }


    // --- Edit Entry Modal & its Buttons ---
    const editEntryModalElement = document.getElementById('entryModal'); // Shared Modal ID from partial
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
        const generateEditModalBtn = document.getElementById('generate-modal-btn'); // Shared ID
        const showHideEditModalBtn = document.getElementById('show-hide-modal-btn'); // Shared ID

        // Listener for all edit buttons on cards to trigger modal population
        document.querySelectorAll('.entry-card .edit-btn').forEach(button => {
            button.addEventListener('click', async function(event) {
                event.stopPropagation();
                const entryId = this.getAttribute('data-id'); if (!entryId) return;

                editForm.reset(); editModalTitle.textContent = 'Loading Entry...';
                editModalSubmitBtn.textContent = 'Update Entry'; editModalSubmitBtn.className = 'btn btn-primary';
                editPasswordInput.required = false; editEntryIdInput.value = entryId;
                editForm.action = `/update_entry/${entryId}`; // Set specific update action URL
                if(editModalHelpText) editModalHelpText.style.display = 'block';

                try {
                    const data = await fetchApi(`/get_entry_details/${entryId}`); // Fetch ALL details
                    editLaptopServerInput.value = data.laptop_server || '';
                    editBrandLabelInput.value = data.brand_label || '';
                    editUsernameInput.value = data.entry_username || '';
                    editPasswordInput.value = data.password || ''; // Pre-fill DECRYPTED password
                    editPasswordInput.placeholder = "Leave blank to keep current password";
                    editPasswordInput.type = 'password'; // Ensure it starts hidden
                    if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-fill'; showHideEditModalBtn.title = 'Show Password';}
                    editModalTitle.textContent = `Edit: ${data.laptop_server || 'Entry'}`;
                    // Modal is shown via data-bs-toggle
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
            // console.log("Attaching listener to EDIT modal generate button"); // Debug
            generateEditModalBtn.addEventListener('click', async function() {
                 // console.log("EDIT modal generate button clicked"); // Debug
                 const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true;
                 try {
                     const data = await fetchApi('/generate_password'); // Re-use API
                     if (data.password) { // Check response
                        editPasswordInput.value = data.password; editPasswordInput.type = 'text';
                        if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-slash-fill'; showHideEditModalBtn.title = 'Hide Password'; }
                     } else { throw new Error(data.error || 'API did not return password'); }
                 } catch (error) { alert('Error generating password: ' + error.message); }
                 finally { this.innerHTML = '<i class="bi bi-stars"></i>'; this.disabled = false; } // Restore icon
             });
         } else { if (!generateEditModalBtn) console.error("JS Error: #generate-modal-btn not found"); if (!editPasswordInput) console.error("JS Error: #modal_entry_password not found"); }

         // Show/Hide Button inside Edit Modal
         if (showHideEditModalBtn && editPasswordInput) {
              showHideEditModalBtn.addEventListener('click', function() {
                 const icon = this.querySelector('i'); if(!editPasswordInput || !icon) return;
                 if (editPasswordInput.type === 'password') { editPasswordInput.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; }
                 else { editPasswordInput.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
             });
         } else { if (!showHideEditModalBtn) console.error("JS Error: #show-hide-modal-btn not found"); }

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