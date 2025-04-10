// static/js/vault-v3.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V3 JS Loaded - Final Version");

    // --- API Fetch Helper ---
    async function fetchApi(url, options = {}) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                let errorMsg = `Request failed with status ${response.status}`;
                try { const errorData = await response.json(); errorMsg = errorData.error || errorMsg; } catch (e) {}
                throw new Error(errorMsg);
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
            else { addEntrySection.classList.add('hidden'); this.classList.remove('active'); const form = addEntrySection.querySelector('form'); if(form) form.reset(); }
        });
    } else { if (!addEntrySidebarBtn) console.error("JS Setup Error: #add-entry-sidebar-btn not found."); if (!addEntrySection) console.error("JS Setup Error: #add-entry-section not found."); }

    // --- Add Entry Form Interactions ---
    const addEntryForm = document.getElementById('add-entry-form');
    if (addEntryForm) {
        const generateBtnAdd = addEntryForm.querySelector('#generate-add-btn');
        const passwordFieldAdd = addEntryForm.querySelector('#add_entry_password');
        const showHideBtnAdd = addEntryForm.querySelector('#show-hide-add-btn');
        const cancelBtnAdd = addEntryForm.querySelector('#cancel-add-entry');

        // Generate (Add Form)
        if (generateBtnAdd && passwordFieldAdd) {
            generateBtnAdd.addEventListener('click', async function() {
                const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true;
                try { const data = await fetchApi('/generate_password'); if (data.password) { passwordFieldAdd.value = data.password; passwordFieldAdd.type = 'text'; if(showHideBtnAdd) { const icon = showHideBtnAdd.querySelector('i'); if(icon) icon.className = 'bi bi-eye-slash-fill'; showHideBtnAdd.title = 'Hide Password'; } } else { throw new Error(data.error || 'API did not return password'); } }
                catch (error) { alert('Error generating password: ' + error.message); } finally { this.innerHTML = '<i class="bi bi-stars"></i>'; this.disabled = false; }
            });
        } else { /* Error log */ }
        // Show/Hide (Add Form)
        if (showHideBtnAdd && passwordFieldAdd) {
            showHideBtnAdd.addEventListener('click', function() { const icon = this.querySelector('i'); if(!passwordFieldAdd || !icon) return; if (passwordFieldAdd.type === 'password') { passwordFieldAdd.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; } else { passwordFieldAdd.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; } });
         } else { /* Error log */ }
        // Cancel (Add Form)
        if (cancelBtnAdd) {
             cancelBtnAdd.addEventListener('click', function() { if (addEntrySection) addEntrySection.classList.add('hidden'); if (addEntrySidebarBtn) addEntrySidebarBtn.classList.remove('active'); const form = addEntryForm; if(form) form.reset(); });
        } else { console.error("JS Setup Error: #cancel-add-entry not found"); }
    } else { console.error("JS Setup Error: #add-entry-form not found"); }

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

        // Populate Modal on Edit Button Click
        document.querySelectorAll('.password-entry .edit-btn').forEach(button => {
            button.addEventListener('click', async function(event) {
                event.stopPropagation(); const entryId = this.getAttribute('data-id'); if (!entryId) return;
                editForm.reset(); editModalTitle.textContent = 'Loading...'; editModalSubmitBtn.textContent = 'Update Entry'; editModalSubmitBtn.className = 'btn btn-primary'; editPasswordInput.required = false; editEntryIdInput.value = entryId; editForm.action = `/update_entry/${entryId}`; if(editModalHelpText) editModalHelpText.style.display = 'block';
                try { const data = await fetchApi(`/get_entry_details/${entryId}`); editLaptopServerInput.value = data.laptop_server || ''; editBrandLabelInput.value = data.brand_label || ''; editUsernameInput.value = data.entry_username || ''; editPasswordInput.value = data.password || ''; editPasswordInput.placeholder = "Leave blank to keep current"; editPasswordInput.type = 'password'; if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-fill'; showHideEditModalBtn.title = 'Show Password';} editModalTitle.textContent = `Edit: ${data.laptop_server || 'Entry'}`; }
                catch (error) { alert(`Failed load: ${error.message}`); editModalTitle.textContent = 'Edit Vault Entry'; if(editEntryModalInstance) editEntryModalInstance.hide(); }
            });
        });
         // Reset modal when hidden
         editEntryModalElement.addEventListener('hidden.bs.modal', function (event) { editForm.reset(); editModalTitle.textContent = 'Edit Vault Entry'; editPasswordInput.required = false; editForm.action = '#'; if(editModalHelpText) editModalHelpText.style.display = 'none'; if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-fill'; showHideEditModalBtn.title = 'Show Password';} if(editPasswordInput) editPasswordInput.type = 'password'; });
         // Generate Button (Edit Modal)
         if (generateEditModalBtn && editPasswordInput) {
             generateEditModalBtn.addEventListener('click', async function() { const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true; try { const data = await fetchApi('/generate_password'); if (data.password) { editPasswordInput.value = data.password; editPasswordInput.type = 'text'; if(showHideEditModalBtn) { const icon = showHideEditModalBtn.querySelector('i'); if(icon) icon.className = 'bi bi-eye-slash-fill'; showHideEditModalBtn.title = 'Hide Password'; } } else { throw new Error(data.error || 'API no password'); } } catch (error) { alert('Error generating password: ' + error.message); } finally { this.innerHTML = '<i class="bi bi-stars"></i>'; this.disabled = false; } });
         } else { /* Error log */ }
         // Show/Hide Button (Edit Modal)
         if (showHideEditModalBtn && editPasswordInput) {
              showHideEditModalBtn.addEventListener('click', function() { const icon = this.querySelector('i'); if(!editPasswordInput || !icon) return; if (editPasswordInput.type === 'password') { editPasswordInput.type = 'text'; icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; } else { editPasswordInput.type = 'password'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; } });
         } else { /* Error log */ }
    } else { console.error("JS Setup Error: Edit Modal #entryModal not found."); }

    // --- Show/Hide Stored Password ---
    document.querySelectorAll('.password-entry .show-stored-btn').forEach(button => {
         button.addEventListener('click', async function(event) {
             event.stopPropagation(); const card = this.closest('.password-entry'); if (!card) return; const entryId = this.getAttribute('data-id'); const dotsSpan = card.querySelector('.password-mask'); const textSpan = card.querySelector('.password-revealed'); const icon = this.querySelector('i'); if (!dotsSpan || !textSpan || !icon || !entryId) { console.error("Show/Hide Error: Missing elements", {dotsSpan, textSpan, icon, entryId}); return; }
             if (textSpan.style.display !== 'none') { /* Hide */ textSpan.style.display = 'none'; textSpan.textContent = ''; dotsSpan.style.display = 'inline-block'; icon.className = 'bi bi-eye-fill'; this.title = 'Show Password'; }
             else { /* Show */ if (!textSpan.textContent) { const originalHtml = this.innerHTML; this.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; this.disabled = true; let passwordToShow = ''; try { const data = await fetchApi(`/get_password/${entryId}`); if (data.password !== undefined) passwordToShow = data.password || '(empty)'; else throw new Error(data.error || 'No password data'); } catch (error) { alert('Error: ' + error.message); this.innerHTML = '<i class="bi bi-eye-fill"></i>'; this.disabled = false; return; } finally { this.disabled = false; } textSpan.textContent = passwordToShow; }
                 if (textSpan.textContent || textSpan.textContent === '') { textSpan.style.display = 'inline-block'; dotsSpan.style.display = 'none'; const currentIcon = this.querySelector('i'); if (currentIcon){ currentIcon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password'; } else { this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>'; this.title = 'Hide Password'; } } }
         });
    });

    // --- Copy Stored Password ---
    document.querySelectorAll('.password-entry .copy-btn').forEach(button => {
         button.addEventListener('click', async function(event) {
             event.stopPropagation(); if (!navigator.clipboard) { alert('Clipboard API not permitted.'); return; }
             const entryId = this.getAttribute('data-id'); const icon = this.querySelector('i'); const originalIconClass = icon ? icon.className : 'bi bi-clipboard-fill';
             if (icon) icon.className = 'spinner-border spinner-border-sm text-primary'; this.disabled = true; this.title = 'Copying...';
             try { const data = await fetchApi(`/get_password/${entryId}`); if (data.password === undefined) throw new Error(data.error || 'No password data'); await navigator.clipboard.writeText(data.password); if (icon) icon.className = 'bi bi-check-lg text-success'; this.title = 'Copied!'; setTimeout(() => { if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }, 1500); }
             catch (error) { console.error("Copy error:", error); alert("Failed to copy: " + error.message); if (icon) icon.className = originalIconClass; this.disabled = false; this.title = 'Copy Password'; }
         });
    });

}); // End DOMContentLoaded