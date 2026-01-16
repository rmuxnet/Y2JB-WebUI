document.addEventListener('DOMContentLoaded', () => {
    populateRepoChecklist();
});

function toggleRepoList(event) {
    event.stopPropagation();
    const list = document.getElementById('repo-checklist');
    list.classList.toggle('hidden');
}

document.addEventListener('click', (e) => {
    const list = document.getElementById('repo-checklist');
    if (list && !list.classList.contains('hidden') && !e.target.closest('.relative')) {
        list.classList.add('hidden');
    }
});

async function populateRepoChecklist() {
    try {
        const response = await fetch('/list_repos');
        const repos = await response.json();
        const container = document.getElementById('repo-items');
        
        container.innerHTML = repos.map(repo => `
            <label class="flex items-center px-4 py-2 hover:bg-white/5 cursor-pointer gap-3 transition-colors">
                <input type="checkbox" value="${repo}" class="repo-checkbox rounded border-gray-700 bg-transparent text-brand-blue focus:ring-brand-blue">
                <span class="text-xs font-mono opacity-80">${repo}</span>
            </label>
        `).join('');

    } catch (error) {
        console.error('Failed to load repo list:', error);
    }
}

async function updatePayloads() {
    const btn = document.getElementById('update-btn');
    const checkboxes = document.querySelectorAll('.repo-checkbox:checked');
    const updateAll = document.getElementById('update-all').checked;
    
    let targets = [];
    if (updateAll) {
        targets = ['all'];
    } else {
        checkboxes.forEach(cb => targets.push(cb.value));
    }

    if (targets.length === 0 && !updateAll) {
        Toast.show('Please select at least one payload to update', 'warning');
        return;
    }

    const originalContent = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin text-xs"></i><span>Updating...</span>';
    Toast.show('Checking for updates...', 'info');

    try {
        const response = await fetch('/update_repos', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targets })
        });

        const result = await response.json();

        if (result.success) {
            if (result.updated.length > 0) {
                Toast.show(`Updated: ${result.updated.join(', ')}`, 'success');
                if(window.loadpayloads) await window.loadpayloads(); 
            } else if (result.errors && result.errors.length > 0) {
                Toast.show(`Errors: ${result.errors[0]}`, 'error');
            } else {
                Toast.show('All payloads are already up to date', 'success');
            }
        } else {
            Toast.show(result.message || 'Update failed', 'error');
        }

    } catch (error) {
        console.error(error);
        Toast.show('Connection error during update', 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalContent;
    }
}
