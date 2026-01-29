document.addEventListener('DOMContentLoaded', () => {
    pollStatus();
    setInterval(pollStatus, 3000);
});

function pollStatus() {
    fetch('/api/netflix/status')
        .then(res => res.json())
        .then(data => {
            updateIndicator('status-proxy', data.proxy);
            updateIndicator('status-ws', data.websocket);
        });
}

function updateIndicator(id, isActive) {
    const el = document.getElementById(id);
    if (isActive) {
        el.innerText = "RUNNING";
        el.className = "text-xs font-bold px-2 py-1 rounded uppercase tracking-wider bg-green-500 text-white";
    } else {
        el.innerText = "STOPPED";
        el.className = "text-xs font-bold px-2 py-1 rounded uppercase tracking-wider bg-gray-500 text-white";
    }
}

function saveConfig() {
    const ip = document.getElementById('host-ip').value;
    const port = document.getElementById('host-port').value;
    
    if (!ip) return Toast.show("Please enter an IP address.", "warning");

    fetch('/api/netflix/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, port })
    })
    .then(res => res.json())
    .then(data => Toast.show(data.message, data.success ? "success" : "error"));
}

function generateCerts() {
    const btn = document.querySelector('button[onclick="generateCerts()"]');
    const out = document.getElementById('cert-output');
    
    btn.disabled = true;
    out.innerText = "Generating...";
    
    fetch('/api/netflix/cert', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            btn.disabled = false;
            out.innerText = data.message;
            if (data.success) out.style.color = "#10b981";
            else out.style.color = "#ef4444";
        });
}

function controlService(action) {
    fetch('/api/netflix/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action })
    })
    .then(res => res.json())
    .then(data => {
        if (!data.success) Toast.show(data.message, "error");
        pollStatus();
    });
}