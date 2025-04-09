// static/js/vault-v3.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V3 JS Loaded - Fixing Edit Action & Generate");

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

    // --- Sidebar Add Entry Toggle ---
    const addEntrySidebarBtn = document.getElementById('add-entry-sidebar-btn');
    const addEntrySection = document.getElementById('add-entry-section');
    if (addEntrySidebarBtn && addEntrySection) {
        addEntrySidebarBtn.addEventListener('click', function(event) {
            event.preventDefault();
            const isHidden = addEntrySection.classList.contains('hidden');
            if (isHidden) { addEntrySection.classList.remove('hidden'); this.classList.add('active'); setTimeout(() => addEntrySection.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50); }
            else { addEntrySection.classList.add('hidden'); this.classList.remove('active'); }
        });
    } else { /* Error logging */ }

    // --- Add Entry Form Interactions ---
    const addEntryForm = document.getElementById('add-entry-form');
    if (addEntryForm) {
        const generateBtnAdd = addEntryForm.querySelector('#generate-add-btn'); // Specific ID
        const passwordFieldAdd = addEntryForm.querySelector('#add_entry_password'); // Specific ID
        const showHideBtnAdd = addEntryForm.querySelector('#show-hide-add-btn'); // Specific ID
        const cancelBtnAdd = addEntryForm.querySelector('#cancel-add-entry');

        // Generate Password Button (Add Form)
        if (generateBtnAdd && passwordFieldAdd) {
            console.log("Attaching listener to ADD form generate button");
            generateBtnAdd.addEventListener('click', async function() {
                console.log("ADD form generate button clicked");
                const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true;
                try {
                    const data = await fetchApi('/generate_password');
                    if (data.password) { // Check if password exists in response
                        passwordFieldAdd.value = data.password; passwordFieldAdd.type = 'text';
                        if(showHideBtnAdd) { const icon = showHideBtnAdd.querySelector('i'); if(icon) icon.className = 'bi bi-eye-slash-fill'; showHideBtnAdd.title = 'Hide Password'; }
                    } else { throw new Error(data.error || 'API did not return a password'); } // Throw error if no password key
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
         }

        // Cancel Button (Add Form)
        if (cancelBtnAdd && addSection && addSidebarBtn) {
            cancelBtnAdd.addEventListener('click', function() {
                addSection.classList.add('hidden'); addSidebarBtn.classList.remove('active');
                const form = addSection.querySelector('form'); if(form) form.reset();
            });
        }

    } else { console.error("JS Error: Add Entry Form #add-entry-form not found"); }


    // --- Edit Entry Modal & its Buttons ---
    const editEntryModalElement = document.getElementById('entryModal'); // Shared Modal ID
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

                // Prepare Modal for Editing state
                editForm.reset(); editModalTitle.textContent = 'Loading Entry...';
                editModalSubmitBtn.textContent = 'Update Entry'; editModalSubmitBtn.className = 'btn btn-primary';
                editPasswordInput.required = false; editEntryIdInput.value = entryId;
                // --- >>> FIX: Set Form Action <<< ---
                editForm.action = `/update_entry/${entryId}`;
                // --- >>> END FIX <<< ---
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
         editEntryModalElement.addEventListener('hidden.bs.modal', function (event) { /* ... reset logic ... */ });

         // Generate Button inside Edit Modal
         if (generateEditModalBtn && editPasswordInput) {
            console.log("Attaching listener to EDIT modal generate button");
            generateEditModalBtn.addEventListener('click', async function() {
                console.log("EDIT modal generate button clicked");
                const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true;
                try {
                    const data = await fetchApi('/generate_password');
                    if (data.password) { // Check if password exists
                        editPasswordInput.value = data.password; editPasswordInput.type = 'text';
                        if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-slash-fill'; showHideEditModalBtn.title = 'Hide Password'; }
                    } else { throw new Error(data.error || 'API did not return a password'); }
                } catch (error) { alert('Error generating password: ' + error.message); }
                finally { this.innerHTML = '<i class="bi bi-stars"></i>'; this.disabled = false; } // Restore icon
             });
         } else { if (!generateEditModalBtn) console.error("JS Error: #generate-modal-btn not found"); if (!editPasswordInput) console.error("JS Error: #modal_entry_password not found"); }

         // Show/Hide Button inside Edit Modal
         if (showHideEditModalBtn && editPasswordInput) {
              showHideEditModalBtn.addEventListener('click', function() { /* ... show/hide logic ... */ });
         } else { if (!showHideEditModalBtn) console.error("JS Error: #show-hide-modal-btn not found"); }

    } // End if(editEntryModalElement)


    // --- Show/Hide Stored Password in Vault Cards ---
    document.querySelectorAll('.entry-card .show-stored-btn').forEach(button => { /* ... unchanged ... */ });

    // --- Copy Stored Password from Vault Cards ---
    document.querySelectorAll('.entry-card .copy-btn').forEach(button => { /* ... unchanged ... */ });

}); // End DOMContentLoaded