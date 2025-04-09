// static/js/vault-v2.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V2 JS Loaded - Edit Modal Logic Added");

    // --- API Fetch Helper (as before) ---
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

    // --- Sidebar Add Entry Toggle (as before) ---
    const addEntrySidebarBtn = document.getElementById('add-entry-sidebar-btn');
    const addEntrySection = document.getElementById('add-entry-section');
    if (addEntrySidebarBtn && addEntrySection) { /* ... toggle logic ... */
        addEntrySidebarBtn.addEventListener('click', function(event) {
            event.preventDefault();
            const isHidden = addEntrySection.classList.contains('hidden');
            if (isHidden) { addEntrySection.classList.remove('hidden'); this.classList.add('active'); addEntrySection.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
            else { addEntrySection.classList.add('hidden'); this.classList.remove('active'); }
        });
    }
    const cancelBtn = document.getElementById('cancel-add-entry');
    if (cancelBtn && addSection && addSidebarBtn) { /* ... cancel logic ... */
        cancelBtn.addEventListener('click', function() {
            addSection.classList.add('hidden'); addSidebarBtn.classList.remove('active');
            const form = addSection.querySelector('form'); if(form) form.reset();
        });
    }


    // --- Add Entry Form Generate/Show/Hide (as before) ---
    const addEntryForm = document.getElementById('add-entry-form');
    if (addEntryForm) { /* ... logic for generate/show buttons inside add form ... */
        const generateBtn = addEntryForm.querySelector('#generate-btn');
        const passwordField = addEntryForm.querySelector('#entry_password');
        const showHideBtn = addEntryForm.querySelector('#show-hide-btn');
        // Generate
        if (generateBtn && passwordField) { generateBtn.addEventListener('click', async function() { /* ... generate ... */ }); }
        // Show/Hide
        if (showHideBtn && passwordField) { showHideBtn.addEventListener('click', function() { /* ... show/hide ... */ }); }
    }

    // --- Show/Hide Stored Password in Vault Cards (as before) ---
    document.querySelectorAll('.entry-card .show-stored-btn').forEach(button => { /* ... card show/hide logic ... */ });

    // --- Copy Stored Password from Vault Cards (as before) ---
    document.querySelectorAll('.entry-card .copy-btn').forEach(button => { /* ... card copy logic ... */ });


    // --- NEW: Edit Entry Modal Logic ---
    const editEntryModalElement = document.getElementById('editEntryModal');
    let editEntryModal = null;
    if (editEntryModalElement) {
        editEntryModal = new bootstrap.Modal(editEntryModalElement); // Initialize Bootstrap Modal instance

        // Get references to modal form elements
        const editForm = document.getElementById('edit-entry-modal-form');
        const editEntryIdInput = document.getElementById('edit_entry_id');
        const editLaptopServerInput = document.getElementById('edit_laptop_server');
        const editBrandLabelInput = document.getElementById('edit_brand_label');
        const editUsernameInput = document.getElementById('edit_entry_username');
        const editPasswordInput = document.getElementById('edit_entry_password');
        const editModalTitle = document.getElementById('editEntryModalLabel'); // Optional: Update title

        // Add event listener to ALL edit buttons in the vault
        document.querySelectorAll('.entry-card .edit-btn').forEach(button => {
            button.addEventListener('click', async function() {
                const entryId = this.getAttribute('data-id');
                if (!entryId) return;

                // Show loading state (optional)
                editModalTitle.textContent = 'Loading Entry...';
                editForm.reset(); // Clear previous data
                editEntryIdInput.value = '';
                editForm.action = '#'; // Reset action

                try {
                    // Fetch full entry data (including decrypted password)
                    const data = await fetchApi(`/get_password/${entryId}`); // Re-use get_password API

                    // Populate the modal form
                    editLaptopServerInput.value = data.original_data?.laptop_server || ''; // Assuming API returns original data
                    editBrandLabelInput.value = data.original_data?.brand_label || '';
                    editUsernameInput.value = data.original_data?.entry_username || '';
                    editPasswordInput.value = data.password || ''; // Pre-fill with decrypted password
                    editPasswordInput.placeholder = "Leave blank to keep current password"; // Ensure placeholder is set
                    editEntryIdInput.value = entryId; // Set the hidden ID (though action URL is primary)

                    // Dynamically set the form action URL
                    editForm.action = `/update_entry/${entryId}`;

                    // Update modal title (optional)
                    editModalTitle.textContent = `Edit Entry: ${data.original_data?.laptop_server || 'Entry'}`;

                    // Show the modal
                    editEntryModal.show();

                } catch (error) {
                    console.error("Error fetching entry for edit:", error);
                    alert(`Failed to load entry details: ${error.message}`); // Show error
                    editModalTitle.textContent = 'Edit Vault Entry'; // Reset title on error
                }
            });
        });

        // Optional: Add JS for Generate/Show buttons inside the EDIT modal
        const generateEditModalBtn = document.getElementById('generate-edit-modal-btn');
        const showHideEditModalBtn = document.getElementById('show-hide-edit-modal-btn');

        if (generateEditModalBtn && editPasswordInput) {
            generateEditModalBtn.addEventListener('click', async function() {
                // ... (Generate logic similar to add form, targeting 'edit_entry_password') ...
            });
        }
        if (showHideEditModalBtn && editPasswordInput) {
             showHideEditModalBtn.addEventListener('click', function() {
                // ... (Show/hide logic similar to add form, targeting 'edit_entry_password') ...
             });
        }


    } // End if(editEntryModalElement)

}); // End DOMContentLoaded