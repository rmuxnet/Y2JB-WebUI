async function directDownload() {
    const input = document.getElementById('directUrlInput');
    const url = input.value.trim();
    const btn = document.querySelector('button[onclick="directDownload()"]');

    if (!url) {
        Toast.show('Please enter a valid URL', 'warning');
        return;
    }

    const originalIcon = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
    Toast.show('Downloading payload...', 'info');

    try {
        const response = await fetch('/download_payload_url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const result = await response.json();

        if (response.ok) {
            Toast.show(`Saved as ${result.filename}`, 'success');
            input.value = ''; 
            if(window.loadpayloads) await window.loadpayloads(); 
        } else {
            Toast.show(result.error || 'Download failed', 'error');
        }

    } catch (error) {
        console.error(error);
        Toast.show('Network error: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalIcon;
    }
}
