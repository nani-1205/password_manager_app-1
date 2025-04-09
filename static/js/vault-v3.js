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
            // For now, re-throw to be handled by the caller
            throw error;
        }
    }

    // --- Sidebar Add Entry Toggle ---
    const addEntrySidebarBtn = document.getElementById('add-entry-sidebar-btn');
    const addEntrySection = document.getElementById('add-entry-section');

    if (addEntrySidebarBtn && addEntrySection) {
        addEntrySidebarBtn.addEventListener('click', function(event) {
            event.preventDefault();
            // console.log("Sidebar Add Entry Clicked!"); // Uncomment for debugging if needed

            const isHidden = addEntrySection.classList.contains('hidden');
            if (isHidden) {
                addEntrySection.classList.remove('hidden');
                this.classList.add('active');
                 setTimeout(() => {
                    const section = document.getElementById('add-entry-section');
                    if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
                 }, 50);
            } else {
                addEntrySection.classList.add('hidden');
                this.classList.remove('active');
                 const form = addEntrySection.querySelector('form'); if(form) form.reset();
            }
        });
        // console.log("Sidebar Add Entry listener attached."); // Debug
    } else {
        if (!addEntrySidebarBtn) console.error("JS Setup Error: Sidebar button #add-entry-sidebar-btn not found.");
        if (!addEntrySection) console.error("JS Setup Error: Add entry section #add-entry-section not found.");
    }

    // --- Add Entry Form Interactions ---
    const addEntryForm = document.getElementById('add-entry-form');
    if (addEntryForm) {
        const generateBtnAdd = addEntryForm.querySelector('#generate-add-btn'); // Button specific to Add Form
        const passwordFieldAdd = addEntryForm.querySelector('#add_entry_password'); // Input specific to Add Form
        const showHideBtnAdd = addEntryForm.querySelector('#show-hide-add-btn'); // Button specific to Add Form
        const cancelBtnAdd = addEntryForm.querySelector('#cancel-add-entry'); // Button specific to Add Form

        // Generate Password Button (Add Form)
        if (generateBtnAdd && passwordFieldAdd) {
            // console.log("Attaching listener to ADD form generate button"); // Debug
            generateBtnAdd.addEventListener('click', async function() {
                // console.log("ADD form generate button clicked"); // Debug
                const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>'; this.disabled = true;
                try {
                    const data = await fetchApi('/generate_password');
                    if (data.password) {
                        passwordFieldAdd.value = data.password; passwordFieldAdd.type = 'text';
                        if(showHideBtnAdd) { const icon = showHideBtnAdd.querySelector('i'); if(icon) icon.className = 'bi bi-eye-slash-fill'; showHideBtnAdd.title = 'Hide Password'; }
                    } else { throw new Error(data.error || 'API did not return a password'); }
                } catch (error) { alert('Error generating password: ' + error.message); }
                finally { this.innerHTML = '<i class="bi bi-stars"></i>'; this.disabled = false; }
            });
        } else { if (!generateBtnAdd) console.error("JS Setup Error: #generate-add-btn not found in Add Form"); if (!passwordFieldAdd) console.error("JS Setup Error: #add_entry_password not found in Add Form"); }

        // Show/Hide Password Button (Add Form)
        if (showHideBtnAdd && passwordFieldAdd) {
            showHideBtnAdd.addEventListener('click', function() {
                 const icon = this.querySelector('i'); if(!passwordFieldAdd || !icon) return;
                 if (passwordFieldAdd.type === 'password') { passwordFieldAdd.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; }
                 else { passwordFieldAdd.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
            });
         } else { if (!showHideBtnAdd) console.error("JS Setup Error: #show-hide-add-btn not found in Add Form"); }

        // Cancel Button (Add Form)
        if (cancelBtnAdd) {
             // console.log("Attaching listener to ADD form cancel button"); // Debug
             cancelBtnAdd.addEventListener('click', function() {
                // console.log("Add form cancel button clicked"); // Debug
                // Use variables defined in the higher scope
                if (addEntrySection) { addEntrySection.classList.add('hidden'); }
                else { console.error("Cancel Error: Cannot find #add-entry-section to hide."); }
                if (addEntrySidebarBtn) { addEntrySidebarBtn.classList.remove('active'); }
                else { console.error("Cancel Error: Cannot find #add-entry-sidebar-btn to deactivate."); }
                const form = addEntryForm; if(form) form.reset();
            });
        } else { console.error("JS Setup Error: Add form Cancel button #cancel-add-entry not found"); }

    } else { console.error("JS Setup Error: Add Entry Form #add-entry-form not found"); }


    // --- Edit Entry Modal & its Buttons ---
    const editEntryModalElement = document.getElementById('entryModal'); // Shared Modal ID from partial
    let editEntryModalInstance = null;
    if (editEntryModalElement) {
        editEntryModalInstance = new bootstrap.Modal(editEntryModalElement); // Initialize BS Modal
        const editForm = document.getElementById('entry-modal-form');
        const editEntryIdInput = document.getElementById('modal_entry_id');
        const editLaptopServerInput = document.getElementById('modal_laptop_server');
        const editBrandLabelInput = document.getElementById('modal_brand_label');
        const editUsernameInput = document.getElementById('modal_entry_username');
        const editPasswordInput = document.getElementById('modal_entry_password'); // ID within Modal
        const editModalTitle = document.getElementById('entryModalLabel');
        const editModalSubmitBtn = document.getElementById('modal_submit_button');
        const editModalHelpText = document.getElementById('modalPasswordHelp');
        const generateEditModalBtn = document.getElementById('generate-modal-btn'); // ID within Modal
        const showHideEditModalBtn = document.getElementById('show-hide-modal-btn'); // ID within Modal

        // Listener for all edit buttons on cards to trigger modal population
        document.querySelectorAll('.entry-card .edit-btn').forEach(button => {
            // console.log("Attaching listener to card edit button", button); // Debug
            button.addEventListener('click', async function(event) {
                event.stopPropagation();
                const entryId = this.getAttribute('data-id'); if (!entryId) { console.error("Edit button missing data-id"); return; }
                console.log("Edit button clicked for ID:", entryId); // Debug

                // Prepare Modal for Editing state
                editForm.reset(); editModalTitle.textContent = 'Loading Entry...';
                editModalSubmitBtn.textContent = 'Update Entry'; editModalSubmitBtn.className = 'btn btn-primary';
                editPasswordInput.required = false; editEntryIdInput.value = entryId;
                editForm.action = `/update_entry/${entryId}`; // Set specific update action URL
                if(editModalHelpText) editModalHelpText.style.display = 'block';

                try {
                    console.log("Fetching details for edit modal:", entryId); // Debug
                    const data = await fetchApi(`/get_entry_details/${entryId}`); // Fetch ALL details
                    console.log("Fetched edit details:", data); // Debug

                    // Populate form fields
                    if (editLaptopServerInput) editLaptopServerInput.value = data.laptop_server || '';
                    if (editBrandLabelInput) editBrandLabelInput.value = data.brand_label || '';
                    if (editUsernameInput) editUsernameInput.value = data.entry_username || '';
                    if (editPasswordInput) {
                        editPasswordInput.value = data.password || ''; // Pre-fill DECRYPTED password
                        editPasswordInput.placeholder = "Leave blank to keep current password";
                        editPasswordInput.type = 'password'; // Ensure it starts hidden
                    }
                    // Reset show/hide button state
                    if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-fill'; showHideEditModalBtn.title = 'Show Password';}

                    if(editModalTitle) editModalTitle.textContent = `Edit: ${data.laptop_server || 'Entry'}`;
                    // Modal is shown via data-bs-toggle="modal" attribute on the button

                } catch (error) {
                    console.error("Error fetching entry for edit:", error);
                    alert(`Failed to load entry details: ${error.message}`);
                    editModalTitle.textContent = 'Edit Vault Entry'; // Reset title on error
                    if(editEntryModalInstance) editEntryModalInstance.hide(); // Hide if fetch fails
                }
            });
        });

         // Reset modal state when hidden
         editEntryModalElement.addEventListener('hidden.bs.modal', function (event) {
             editForm.reset(); editModalTitle.textContent = 'Edit Vault Entry';
             editPasswordInput.required = false; editForm.action = '#'; // Clear action
             if(editModalHelpText) editModalHelpText.style.display = 'none';
             // Reset show/hide button in modal
             if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-fill'; showHideEditModalBtn.title = 'Show Password';}
             if(editPasswordInput) editPasswordInput.type = 'password';
         });

         // Generate Button inside Edit Modal
         if (generateEditModalBtn && editPasswordInput) {
            // console.log("Attaching listener to EDIT modal generate button"); // Debug
            generateEditModalBtn.addEventListener('click', async function() {
                 // console.log("EDIT modal generate button clicked"); // Debug
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
         } else { if (!generateEditModalBtn) console.error("JS Error: Edit Modal #generate-modal-btn not found"); if (!editPasswordInput) console.error("JS Error: Edit Modal #modal_entry_password not found"); }

         // Show/Hide Button inside Edit Modal
         if (showHideEditModalBtn && editPasswordInput) {
              showHideEditModalBtn.addEventListener('click', function() {
                 const icon = this.querySelector('i'); if(!editPasswordInput || !icon) return;
                 if (editPasswordInput.type === 'password') { editPasswordInput.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; }
                 else { editPasswordInput.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
             });
         } else { if (!showHideEditModalBtn) console.error("JS Error: Edit Modal #show-hide-modal-btn not found"); }

    } else { console.error("JS Setup Error: Edit Modal #entryModal not found."); }


    // --- Show/Hide Stored Password in Vault Cards ---
    document.querySelectorAll('.entry-card .show-stored-btn').forEach(button => {
         // console.log("Attaching listener to VAULT CARD show/hide button", button); // Debug
         button.addEventListener('click', async function(event) {
             event.stopPropagation();
             // console.log("Vault card show/hide clicked!", this.getAttribute('data-id')); // Debug

             const card = this.closest('.password-entry'); // Use the correct class
             if (!card) { console.error("Show/Hide Error: Cannot find parent .password-entry"); return; }

             const entryId = this.getAttribute('data-id');
             const dotsSpan = card.querySelector('.password-mask');
             const textSpan = card.querySelector('.password-revealed');
             const icon = this.querySelector('i');

             // console.log("Found Elements:", { entryId, dotsSpan, textSpan, icon }); // Debug

             if (!dotsSpan || !textSpan || !icon || !entryId) {
                 console.error("Show/Hide Error: Missing required elements", {dotsSpan, textSpan, icon, entryId});
                 return;
             }

             if (textSpan.style.display !== 'none') { // --- HIDE ACTION ---
                 // console.log("Hiding password"); // Debug
                 textSpan.style.display = 'none'; textSpan.textContent = ''; // Clear password
                 dotsSpan.style.display = 'inline-block';
                 icon.className = 'bi bi-eye-fill'; this.title = 'Show Password';
             } else { // --- SHOW ACTION ---
                 if (!textSpan.textContent) { // Fetch only if needed
                     // console.log("Fetching password to show..."); // Debug
                     const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>'; this.disabled = true;
                     let passwordToShow = ''; // Store fetched password
                     try {
                         const data = await fetchApi(`/get_password/${entryId}`);
                         // console.log("API Response for show:", data); // Debug
                         if (data.password !== undefined) passwordToShow = data.password || '(empty)';
                         else throw new Error(data.error || 'No password data');
                     } catch (error) {
                         console.error("Error fetching password for show:", error);
                         alert('Error: ' + error.message);
                         this.innerHTML = '<i class="bi bi-eye-fill"></i>'; this.disabled = false; return;
                     } finally { this.disabled = false; }

                     // Update UI only after potential fetch completes
                     textSpan.textContent = passwordToShow;
                     if (textSpan.textContent && textSpan.textContent !== '(empty)') {
                        if (this.querySelector('.spinner-border')) { this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>'; } // Restore icon
                        icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password';
                     } else { // Handle empty password or error during fetch
                        if (!this.querySelector('i')) { this.innerHTML = '<i class="bi bi-eye-fill"></i>'; } // Restore icon
                         icon.className = 'bi bi-eye-fill'; this.title = 'Show Password';
                         textSpan.textContent = ''; // Ensure it's empty if there was an error or no password
                     }
                 } else { /* console.log("Password already fetched, just showing."); */ }

                 // Ensure correct display state after fetch or if already fetched
                 if (textSpan.textContent || textSpan.textContent === '') { // Check if text content is set
                    textSpan.style.display = 'inline-block'; dotsSpan.style.display = 'none';
                    icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password';
                    if (!this.querySelector('i')) { this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>'; } // Restore icon just in case
                 }
             }
         });
    }); // End forEach show-stored-btn

    // --- Copy Stored Password from Vault Cards ---
    document.querySelectorAll('.entry-card .copy-btn').forEach(button => {
         button.addEventListener('click', async function(event) {
             event.stopPropagation(); if (!navigator.clipboard) { alert('Clipboard API not permitted.'); return; }
             const entryId = this.getAttribute('data-id'); const icon = this.querySelector('i');
             const originalIconClass = icon ? icon.className : 'bi bi-clipboard-fill';
             if (icon) icon.className = 'spinner-border spinner-border-sm text-primary'; this.disabled = true; this.title = 'Copying...';
             try { const data = await fetchApi(`/get_password/${entryId}`);
                 if (data.password === undefined) throw new Error(data.error || 'No password data');
                 await navigator.clipboard.writeText(data.password);
                 if (icon) icon.className = 'bi bi-check-lg text-success'; this.title = 'Copied!';
                 setTimeout(() => { if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }, 1500);
             } catch (error) { console.error("Copy error:", error); alert("Failed to copy: " + error.message); if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }
         });
    });

}); // End DOMContentLoaded