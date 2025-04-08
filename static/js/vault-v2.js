// static/js/vault-v2.js

document.addEventListener('DOMContentLoaded', function() {
    console.log("Quantum Vault V2 JS Loaded - Sidebar Toggle Added");

    // --- Sidebar Add Entry Toggle ---
    const addEntrySidebarBtn = document.getElementById('add-entry-sidebar-btn');
    const addEntrySection = document.getElementById('add-entry-section');

    if (addEntrySidebarBtn && addEntrySection) {
        addEntrySidebarBtn.addEventListener('click', function(event) {
            event.preventDefault(); // Prevent default if it's an anchor tag

            // Toggle visibility of the form section
            const isHidden = addEntrySection.classList.contains('hidden');
            if (isHidden) {
                addEntrySection.classList.remove('hidden');
                this.classList.add('active'); // Highlight sidebar item
                // Optional: Scroll to the form
                addEntrySection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            } else {
                addEntrySection.classList.add('hidden');
                this.classList.remove('active'); // Remove highlight
            }
        });
    } else {
        console.warn("Sidebar add entry button or section not found.");
    }

    // --- API Fetch Helper ---
    async function fetchApi(url, options = {}) {
        // ... (fetchApi function remains the same) ...
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

    // --- Password Generation in Add Entry Section ---
    const addEntryForm = document.getElementById('add-entry-form'); // Get the form itself
    if (addEntryForm) {
        const generateBtn = addEntryForm.querySelector('#generate-btn'); // Button inside the form
        const passwordField = addEntryForm.querySelector('#entry_password'); // Field inside the form

        if (generateBtn && passwordField) {
            generateBtn.addEventListener('click', async function() {
                this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
                this.disabled = true;
                try {
                    const data = await fetchApi('/generate_password');
                    passwordField.value = data.password;
                    // If using show/hide, maybe show it briefly
                     const showHideBtn = addEntryForm.querySelector('#show-hide-btn');
                     const icon = showHideBtn ? showHideBtn.querySelector('i') : null;
                     passwordField.type = 'text'; // Ensure it's visible
                     if(showHideBtn && icon) {
                         icon.className = 'bi bi-eye-slash-fill'; // Show hide icon
                         showHideBtn.title = 'Hide Password';
                         showHideBtn.innerHTML = `<i class="bi bi-eye-slash-fill"></i> Hide`;
                     }

                } catch (error) {
                    alert('Error generating password: ' + error.message);
                } finally {
                    this.innerHTML = '<i class="bi bi-stars"></i>'; // Restore original icon/text
                    this.disabled = false;
                }
            });
        }

        // Show/Hide Password in Add Entry Section
        const showHideBtn = addEntryForm.querySelector('#show-hide-btn');
        if (showHideBtn && passwordField) {
            showHideBtn.addEventListener('click', function() {
                const icon = this.querySelector('i');
                if (passwordField.type === 'password') {
                    passwordField.type = 'text';
                    if(icon) icon.className = 'bi bi-eye-slash-fill';
                    this.title = 'Hide Password'; this.innerHTML = `<i class="bi bi-eye-slash-fill"></i> Hide`;
                } else {
                    passwordField.type = 'password';
                    if(icon) icon.className = 'bi bi-eye-fill';
                    this.title = 'Show Password'; this.innerHTML = `<i class="bi bi-eye-fill"></i> Show`;
                }
            });
        }
    } // end if(addEntryForm)


    // --- Show/Hide Stored Password in Vault Cards ---
    document.querySelectorAll('.entry-card .show-stored-btn').forEach(button => {
        // ... (Show/hide logic for cards remains the same as previous version) ...
        button.addEventListener('click', async function(event) {
            event.stopPropagation();
            const card = this.closest('.entry-card'); if (!card) return;
            const entryId = this.getAttribute('data-id');
            const dotsSpan = card.querySelector('.password-mask');
            const textSpan = card.querySelector('.password-revealed');
            const icon = this.querySelector('i');
            if (!dotsSpan || !textSpan || !icon) return;

            if (textSpan.style.display !== 'none') { // Hide
                textSpan.style.display = 'none'; textSpan.textContent = '';
                dotsSpan.style.display = 'inline-block';
                icon.className = 'bi bi-eye-fill'; this.title = 'Show Password';
            } else { // Show
                if (!textSpan.textContent) {
                     this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>'; this.disabled = true;
                     try {
                        const data = await fetchApi(`/get_password/${entryId}`);
                        textSpan.textContent = data.password || '(empty)';
                    } catch (error) {
                         alert('Error fetching password: ' + error.message);
                         this.innerHTML = '<i class="bi bi-eye-fill"></i>'; this.disabled = false; return;
                     } finally { this.disabled = false; }
                }
                textSpan.style.display = 'inline-block'; dotsSpan.style.display = 'none';
                icon.className = 'bi bi-eye-slash-fill'; this.title = 'Hide Password';
                 if (!this.querySelector('i')) this.innerHTML = '<i class="bi bi-eye-slash-fill"></i>';
            }
        });
    });

    // --- Copy Stored Password from Vault Cards ---
    document.querySelectorAll('.entry-card .copy-btn').forEach(button => {
        // ... (Copy logic for cards remains the same as previous version) ...
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