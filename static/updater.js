document.addEventListener('DOMContentLoaded', () => {
    const allCheckbox = document.getElementById('update-all');

    fetch('/list_repos')
        .then(r => r.json())
        .then(repos => {
            const container = document.getElementById('repo-items');
            repos.forEach(name => {
                const label = document.createElement('label');
                label.className = 'flex items-center px-4 py-2 hover:bg-white/5 cursor-pointer gap-3';
                label.innerHTML = `
                    <input type="checkbox" name="repo-target" value="${name}" class="rounded border-gray-700 bg-transparent text-brand-blue focus:ring-brand-blue" onchange="toggleIndividual(this)">
                    <span class="text-xs">${name}</span>
                `;
                container.appendChild(label);
            });
        });

    allCheckbox.addEventListener('change', () => {
        document.querySelectorAll('input[name="repo-target"]').forEach(cb => {
            cb.checked = allCheckbox.checked;
        });
    });
});

function toggleIndividual() {
    const allCheckbox = document.getElementById('update-all');
    const individuals = document.querySelectorAll('input[name="repo-target"]');
    const allTicked = Array.from(individuals).every(cb => cb.checked);
    allCheckbox.checked = allTicked;
}

function toggleRepoList(e) {
    if (e) e.stopPropagation();
    document.getElementById('repo-checklist').classList.toggle('hidden');
}

document.addEventListener('click', (e) => {
    const list = document.getElementById('repo-checklist');
    if (list && !list.classList.contains('hidden') && !list.contains(e.target)) {
        list.classList.add('hidden');
    }
});

function updatePayloads() {
    const allChecked = document.getElementById('update-all').checked;
    const targets = allChecked ? ['all'] : Array.from(document.querySelectorAll('input[name="repo-target"]:checked')).map(cb => cb.value);
    
    if (targets.length === 0) return alert("Please select at least one payload.");
    if (!confirm(`Update ${allChecked ? 'all payloads' : targets.length + ' selected payloads'}?`)) return;
    
    const btn = document.getElementById('update-btn');
    const originalText = btn.innerHTML;
    
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Updating...';
    btn.disabled = true;

    fetch('/update_repos', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets })
    })
    .then(response => response.json())
    .then(data => {
        btn.innerHTML = originalText;
        btn.disabled = false;
        
        if (data.success) {
            let msg = "Update Finished.\n\n";
            if (data.updated.length > 0) msg += "Updated: " + data.updated.join(", ");
            else msg += "Already up to date.";
            alert(msg);
            location.reload();
        } else {
            alert("Update Failed: " + (data.message || "Error"));
        }
    })
    .catch(error => {
        btn.innerHTML = originalText;
        btn.disabled = false;
        alert("Network Error: " + error);
    });
}
