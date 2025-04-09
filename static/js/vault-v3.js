// static/js/vault-v3.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V3 JS Loaded - Final Check");

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
    const addEntrySidebarBtn = document.getElementById('add-entry-sidebar-btn');
    const addEntrySection = document.getElementById('add-entry-section');

    if (addEntrySidebarBtn && addEntrySection) {
        addEntrySidebarBtn.addEventListener('click', function(event) {
            event.preventDefault(); // Prevent default link behavior
            console.log("Sidebar Add Entry Clicked!"); // Debug

            const isHidden = addEntrySection.classList.contains('hidden');
            if (isHidden) {
                addEntrySection.classList.remove('hidden');
                this.classList.add('active'); // Highlight sidebar item
                 setTimeout(() => { // Delay scroll slightly
                    const section = document.getElementById('add-entry-section');
                    if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
                 }, 50);
            } else {
                addEntrySection.classList.add('hidden');
                this.classList.remove('active'); // Remove highlight
                 const form = addEntrySection.querySelector('form'); if(form) form.reset(); // Reset form
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
        const generateBtnAdd = addEntryForm.querySelector('#generate-add-btn');
        const passwordFieldAdd = addEntryForm.querySelector('#add_entry_password'); // Use correct ID
        const showHideBtnAdd = addEntryForm.querySelector('#show-hide-add-btn'); // Use correct ID
        const cancelBtnAdd = addEntryForm.querySelector('#cancel-add-entry');

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
        } else { if (!generateBtnAdd) console.error("JS Error: #generate-add-btn not found in Add Form"); if (!passwordFieldAdd) console.error("JS Error: #add_entry_password not found in Add Form"); }

        // Show/Hide Password Button (Add Form)
        if (showHideBtnAdd && passwordFieldAdd) {
            showHideBtnAdd.addEventListener('click', function() {
                 const icon = this.querySelector('i'); if(!passwordFieldAdd || !icon) return;
                 if (passwordFieldAdd.type === 'password') { passwordFieldAdd.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; }
                 else { passwordFieldAdd.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
            });
         }

        // Cancel Button (Add Form)
        if (cancelBtnAdd) {
             // console.log("Attaching listener to ADD form cancel button"); // Debug
             cancelBtnAdd.addEventListener('click', function() {
                // console.log("Add form cancel button clicked"); // Debug
                // Use variables defined in outer scope (should be accessible)
                if (addEntrySection) { addEntrySection.classList.add('hidden'); }
                else { console.error("Cancel Error: Cannot find #add-entry-section to hide."); }
                if (addEntrySidebarBtn) { addEntrySidebarBtn.classList.remove('active'); }
                else { console.error("Cancel Error: Cannot find #add-entry-sidebar-btn to deactivate."); }
                const form = addEntryForm; if(form) form.reset();
            });
        } else { console.error("JS Error: Add form Cancel button #cancel-add-entry not found"); }

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
        const editPasswordInput = document.getElementById('modal_entry_password'); // Correct ID
        const editModalTitle = document.getElementById('entryModalLabel');
        const editModalSubmitBtn = document.getElementById('modal_submit_button');
        const editModalHelpText = document.getElementById('modalPasswordHelp');
        const generateEditModalBtn = document.getElementById('generate-modal-btn'); // Correct ID
        const showHideEditModalBtn = document.getElementById('show-hide-modal-btn'); // Correct ID

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
            // console.log("Attaching listener to EDIT modal generate button"); // Debug
            generateEditModalBtn.addEventListener('click', async function() {
                 // console.log("EDIT modal generate button clicked"); // Debug
                 const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true;
                 try {
                     const data = await fetchApi('/generate_password');
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
         // console.log("Attaching listener to VAULT CARD show/hide button", button); // DEBUG
         button.addEventListener('click', async function(event) {
             event.stopPropagation(); // Prevent card click event if any
             // console.log("Vault card show/hide clicked!", this.getAttribute('data-id')); // DEBUG

             const card = this.closest('.entry-card'); // Find the parent card
             if (!card) { console.error("Cannot find parent .entry-card"); return; }

             const entryId = this.getAttribute('data-id');
             const dotsSpan = card.querySelector('.password-mask'); // Find mask within THIS card
             const textSpan = card.querySelector('.password-revealed'); // Find text span within THIS card
             const icon = this.querySelector('i');

             // console.log("Found Elements:", { entryId, dotsSpan, textSpan, icon }); // DEBUG

             if (!dotsSpan || !textSpan || !icon || !entryId) {
                 console.error("Missing required elements for show/hide", {dotsSpan, textSpan, icon, entryId}); // DEBUG
                 return;
             }

             // Check if text is currently visible (based on its display style)
             if (textSpan.style.display !== 'none') {
                 // --- HIDE ACTION ---
                 // console.log("Hiding password"); // DEBUG
                 textSpan.style.display = 'none';
                 textSpan.textContent = ''; // Clear password from HTML for security on hide
                 dotsSpan.style.display = 'inline-block'; // Or 'block' if needed by layout
                 icon.className = 'bi bi-eye-fill'; // Show 'eye' icon
                 this.title = 'Show Password';
             } else {
                 // --- SHOW ACTION ---
                 // Fetch only if text content is currently empty
                 if (!textSpan.textContent) {
                     // console.log("Fetching password to show..."); // DEBUG
                     this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>'; // Show loading indicator
                     this.disabled = true;
                     try {
                         const data = await fetchApi(`/get_password/${entryId}`); // Call API
                         // console.log("API Response for show:", data); // DEBUG
                         if (data.password !== undefined) { // Check key exists
                             textSpan.textContent = data.password || '(empty)'; // Populate span
                         } else {
                              throw new Error(data.error || 'No password data');
                         }
                     }
                     catch (error) {
                         console.error("Error fetching password for show:", error); // DEBUG
                         alert('Error fetching password: ' + error.message);
                         this.innerHTML = '<i class="bi bi-eye-fill"></i>'; // Restore icon on error
                         this.disabled = false;
                         return; // Stop execution if fetch failed
                     }
                     finally {
                         this.disabled = false; // Re-enable button
                         // Ensure icon is correct even if loading indicator was fast
                         // Use the eye-slash icon only if we successfully got here without error
                         if (textSpan.textContent !== '(empty)') { // Check content again just before changing icon
                             this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>'; // Show 'eye-slash' icon after fetch
                             this.title = 'Hide Password';
                         } else {
                              this.innerHTML = '<i class="bi bi-eye-fill"></i>'; // Restore default if empty
                         }
                     }
                 } else {
                      // console.log("Password already fetched, just showing."); // DEBUG
                 }
                 // Show text span, hide dots span
                 textSpan.style.display = 'inline-block'; // Or 'block'
                 dotsSpan.style.display = 'none';
                 icon.className = 'bi bi-eye-slash-fill'; // Ensure icon is slash
                 this.title = 'Hide Password';
                 // If the button still has the spinner (e.g., very fast response), ensure icon is restored
                 if (!this.querySelector('i')) {
                     this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>';
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
                 if (data.password === undefined) throw new Error(data.error || 'No password data'); // Check response
                 await navigator.clipboard.writeText(data.password);
                 if (icon) icon.className = 'bi bi-check-lg text-success'; this.title = 'Copied!';
                 setTimeout(() => { if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }, 1500);
             } catch (error) { console.error("Copy error:", error); alert("Failed to copy: " + error.message); if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }
         });
    });

}); // End DOMContentLoaded