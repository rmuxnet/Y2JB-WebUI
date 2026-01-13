window.onload = loadsettings;

async function uploadPayload() {
  try {
    // Get the selected file
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];

    if (!file) {
      alert('Please select a file first!');
      return;
    }

    // Create FormData object
    const formData = new FormData();
    formData.append('file', file);

    // Show upload status
    document.getElementById('uploadStatus').textContent = 'Uploading...';

    // Send to server
    const response = await fetch('/upload_payload', {
      method: 'POST',
      body: formData
      // DONT set Content-Type header - browser will set it automatically with boundary
    });

    if (!response.ok) {
      throw new Error(`Upload failed: ${response.status}`);
    }

    const result = await response.json();
    document.getElementById('uploadStatus').textContent = 'Upload successful!';

    console.log('Server response:', result);
    loadpayloads();
    return result;

  } catch (error) {
    console.error('Upload error:', error);
    document.getElementById('uploadStatus').textContent = `Error: ${error.message}`;
  }
}

async function saveIP() {
    const ipInput = document.getElementById("IP");
    const ipValue = ipInput.value;

    if (ipValue.trim() === "") {
        alert("Please enter an IP address first!");
        return;
    }

    localStorage.setItem("savedIP", ipValue);
}

async function loadIP() {
    const savedIP = localStorage.getItem("savedIP");

    if (savedIP) {
        document.getElementById("IP").value = savedIP;
        console.log(`Loaded IP: ${savedIP}`);
        setip(savedIP);
    } else {
        console.log("No saved IP found.");
    }
}

async function saveAJB() {
    const AJBInput = document.getElementById("AJB-B").checked;

    localStorage.setItem("savedAJB", AJBInput);
    if (AJBInput == "true") {
        document.getElementById("AJB-B").checked = true;
        setajb("true");
        console.log(`Loaded AJB Value: ${savedAJB}`);
    } else {
        document.getElementById("AJB-B").checked = false;
        setajb("false");
        console.log("No saved AJB Value found.");
    }

    window.location.reload();
}

async function loadAJB() {
    const savedAJB = localStorage.getItem("savedAJB");

    if (savedAJB == "true") {
        document.getElementById("AJB-B").checked = true;
        setajb("true");
        console.log(`Loaded AJB Value: ${savedAJB}`);
    } else {
        document.getElementById("AJB-B").checked = false;
        setajb("false");
        console.log("No saved AJB Value found.");
    }
}

async function setajb(str) {
    const newContent = str;
    const response = await fetch('/edit_ajb', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: newContent })
    });
    console.log(response.text());
}

async function setip(str) {
    const newContent = str;
    const response = await fetch('/edit_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: newContent })
    });
    console.log(response.text());
}

async function SendPayload(str="") {
    try {
        const response = await fetch('/send_payload', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                payload: str,
                IP: localStorage.getItem("savedIP")
            })
        });

        const text = await response.text();
        return text;
    } catch (error) {
        console.error('Error:', error);
        alert('Error:' + error);
    }
}

async function DeletePayload(str) {
    try {
        const response = await fetch('/delete_payload', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                payload: str
            })
        });

        const text = await response.text();
        loadpayloads();
        return text;
    } catch (error) {
        console.error('Error:', error);
        alert('Error:' + error);
    }
}

function loadsettings() {
    loadIP();
    loadAJB();
    loadpayloads();
}

async function savesettings(){
    saveIP();
    saveAJB();
}

async function loadpayloads() {
  const response = await fetch('/list_payloads');
  const files = await response.json();

  const listElement = document.getElementById('PL');
  listElement.innerHTML = files.map(file =>
    `<li><a id="PLI">📁 ${file}</a></li>
    <button class="load-btn" onclick="SendPayload('payloads/${file}')">Load Payload</button>
    <button class="delete-btn" onclick="DeletePayload('${file}')">Delete</button>`
  ).join('');
}

document.getElementById('SJB').addEventListener('click', function(event) {
    event.preventDefault();
    SendPayload();
});

async function UpdateY2JB() {
    const btn = document.getElementById('update-btn');
    const originalText = btn.innerText;
    
    try {
        btn.innerText = "Updating...";
        btn.disabled = true;

        const response = await fetch('/update_y2jb', {
            method: 'POST'
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Server returned Status ${response.status} (${response.statusText}). Did you restart the server?`);
        }

        const result = await response.json();
        
        if (result.success) {
            alert(result.message);
        } else {
            alert('Update failed: ' + result.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert(error.message);
    } finally {
        btn.innerText = originalText;
        btn.disabled = false;
    }
}