// static/js/vault-v3.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V3 JS Loaded - Comprehensive Version");

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
                } catch (parseError) {
                    // Ignore if response wasn't JSON
                }
                throw new Error(errorMsg);
            }
            // Handle potentially empty successful responses before parsing JSON
            const text = await response.text();
            return text ? JSON.parse(text) : {};
        } catch (error) {
            console.error(`API Fetch Error (${url}):`, error);
            // Optionally show a user-friendly message via flash or alert
            // alert(`API Error: ${error.message}`); // Simple alert for now
            throw error; // Re-throw for specific handling if needed
        }
    }

    // --- Sidebar Add Entry Section Toggle ---
    const addEntrySidebarBtn = document.getElementById('add-entry-sidebar-btn');
    const addEntrySection = document.getElementById('add-entry-section');

    if (addEntrySidebarBtn && addEntrySection) {
        addEntrySidebarBtn.addEventListener('click', function(event) {
            event.preventDefault(); // Prevent default anchor tag behavior
            console.log("Sidebar Add Entry Clicked"); // Debug

            const isHidden = addEntrySection.classList.contains('hidden');
            if (isHidden) {
                addEntrySection.classList.remove('hidden');
                this.classList.add('active'); // Highlight sidebar item
                // Optional: Scroll to the form
                 setTimeout(() => addEntrySection.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50);
            } else {
                addEntrySection.classList.add('hidden');
                this.classList.remove('active'); // Remove highlight
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
        const generateBtnAdd = addEntryForm.querySelector('#generate-btn');
        const passwordFieldAdd = addEntryForm.querySelector('#entry_password');
        const showHideBtnAdd = addEntryForm.querySelector('#show-hide-btn');
        const cancelBtnAdd = addEntryForm.querySelector('#cancel-add-entry');

        // Generate Password Button (Add Form)
        if (generateBtnAdd && passwordFieldAdd) {
            generateBtnAdd.addEventListener('click', async function() {
                const originalHtml = this.innerHTML;
                this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>'; this.disabled = true;
                try {
                    const data = await fetchApi('/generate_password');
                    passwordFieldAdd.value = data.password;
                    passwordFieldAdd.type = 'text'; // Show generated pass
                    if (showHideBtnAdd) { // Update corresponding show/hide button
                        const icon = showHideBtnAdd.querySelector('i');
                        if(icon) icon.className = 'bi bi-eye-slash-fill';
                        showHideBtnAdd.title = 'Hide Password';
                    }
                } catch (error) { alert('Error generating password: ' + error.message); }
                finally { this.innerHTML = originalHtml; this.disabled = false; }
            });
            // console.log("Add Entry Form Generate listener attached."); // Debug
        }

        // Show/Hide Password Button (Add Form)
        if (showHideBtnAdd && passwordFieldAdd) {
            showHideBtnAdd.addEventListener('click', function() {
                 const icon = this.querySelector('i');
                 if(passwordFieldAdd && icon) {
                    if (passwordFieldAdd.type === 'password') {
                         passwordFieldAdd.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password';
                     } else {
                         passwordFieldAdd.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password';
                     }
                 }
            });
            // console.log("Add Entry Form Show/Hide listener attached."); // Debug
         }

        // Cancel Button (Add Form)
        if (cancelBtnAdd && addSection && addSidebarBtn) {
            cancelBtnAdd.addEventListener('click', function() {
                addSection.classList.add('hidden'); addSidebarBtn.classList.remove('active');
                const form = addSection.querySelector('form'); if(form) form.reset();
            });
            // console.log("Add Entry Form Cancel listener attached."); // Debug
        }

    } // end if(addEntryForm)


    // --- Edit Entry Modal & its Buttons ---
    const editEntryModalElement = document.getElementById('entryModal'); // Shared Modal ID from partial
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
                event.stopPropagation(); // Prevent card click triggering other actions
                const entryId = this.getAttribute('data-id'); if (!entryId) return;

                // Prepare Modal for Editing state
                editForm.reset();
                editModalTitle.textContent = 'Loading Entry...';
                editModalSubmitBtn.textContent = 'Update Entry';
                editModalSubmitBtn.className = 'btn btn-primary';
                editPasswordInput.required = false; // Not strictly required for update
                editEntryIdInput.value = entryId; // Set hidden ID (optional use)
                editForm.action = `/update_entry/${entryId}`; // Set form POST target
                if(editModalHelpText) editModalHelpText.style.display = 'block'; // Show help text for edit

                try {
                    const data = await fetchApi(`/get_entry_details/${entryId}`); // Fetch ALL details
                    // Populate form fields
                    editLaptopServerInput.value = data.laptop_server || '';
                    editBrandLabelInput.value = data.brand_label || '';
                    editUsernameInput.value = data.entry_username || '';
                    editPasswordInput.value = data.password || ''; // Pre-fill DECRYPTED password
                    editPasswordInput.placeholder = "Leave blank to keep current password";
                    editPasswordInput.type = 'password'; // Ensure it starts hidden

                    // Reset show/hide button state
                    if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-fill'; showHideEditModalBtn.title = 'Show Password';}

                    editModalTitle.textContent = `Edit: ${data.laptop_server || 'Entry'}`;
                    // Modal is shown via data-bs-toggle, JS show() not needed here usually

                } catch (error) {
                    alert(`Failed to load entry details: ${error.message}`);
                    editModalTitle.textContent = 'Edit Vault Entry'; // Reset title on error
                    if(editEntryModalInstance) editEntryModalInstance.hide(); // Hide if fetch fails
                }
            });
        });

         // Reset modal state when hidden
         editEntryModalElement.addEventListener('hidden.bs.modal', function (event) {
             editForm.reset();
             editModalTitle.textContent = 'Edit Vault Entry';
             editPasswordInput.required = false;
             editForm.action = '#';
             if(editModalHelpText) editModalHelpText.style.display = 'none';
         });

         // Generate Button inside Edit Modal
         if (generateEditModalBtn && editPasswordInput) {
             generateEditModalBtn.addEventListener('click', async function() {
                 const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true;
                 try {
                     const data = await fetchApi('/generate_password'); // Re-use API
                     editPasswordInput.value = data.password;
                     editPasswordInput.type = 'text'; // Show generated password
                     // Update show/hide button state
                     if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-slash-fill'; showHideEditModalBtn.title = 'Hide Password'; }
                 } catch (error) { alert('Error generating password: ' + error.message); }
                 finally { this.innerHTML = '<i class="bi bi-stars"></i>'; this.disabled = false; }
             });
             // console.log("Edit Modal Generate listener attached."); // Debug
         } else { if(!generateEditModalBtn) console.error("JS Error: Edit modal generate button not found"); if(!editPasswordInput) console.error("JS Error: Edit modal password field not found"); }

         // Show/Hide Button inside Edit Modal
         if (showHideEditModalBtn && editPasswordInput) {
              showHideEditModalBtn.addEventListener('click', function() {
                 const icon = this.querySelector('i'); if(!editPasswordInput || !icon) return;
                 if (editPasswordInput.type === 'password') { editPasswordInput.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; }
                 else { editPasswordInput.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
             });
            //  console.log("Edit Modal Show/Hide listener attached."); // Debug
         } else { if(!showHideEditModalBtn) console.error("JS Error: Edit modal show/hide button not found"); }

    } // End if(editEntryModalElement)


    // --- Show/Hide Stored Password in Vault Cards ---
    document.querySelectorAll('.entry-card .show-stored-btn').forEach(button => {
         button.addEventListener('click', async function(event) {
             event.stopPropagation(); const card = this.closest('.entry-card'); if (!card) return;
             const entryId = this.getAttribute('data-id'); const dotsSpan = card.querySelector('.password-mask');
             const textSpan = card.querySelector('.password-revealed'); const icon = this.querySelector('i');
             if (!dotsSpan || !textSpan || !icon) return;

             if (textSpan.style.display !== 'none') { // Hide Action
                 textSpan.style.display = 'none'; textSpan.textContent = ''; // Clear password
                 dotsSpan.style.display = 'inline-block'; // Or 'block' depending on CSS
                 icon.className = 'bi bi-eye-fill'; this.title = 'Show Password';
             } else { // Show Action
                 if (!textSpan.textContent) { // Fetch only if needed
                     this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>'; this.disabled = true;
                     try { const data = await fetchApi(`/get_password/${entryId}`); textSpan.textContent = data.password || '(empty)'; }
                     catch (error) { alert('Error: ' + error.message); this.innerHTML = '<i class="bi bi-eye-fill"></i>'; this.disabled = false; return; }
                     finally { this.disabled = false; }
                 }
                 textSpan.style.display = 'inline-block'; dotsSpan.style.display = 'none';
                 icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password';
                 if (!this.querySelector('i')) this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>'; // Restore icon
             }
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
                 setTimeout(() => { if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }, 1500); // Revert after 1.5s
             } catch (error) { console.error("Copy error:", error); alert("Failed to copy: " + error.message); if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }
         });
    });

}); // End DOMContentLoaded