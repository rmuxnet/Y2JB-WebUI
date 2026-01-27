import os
from src.download_payload import handle_url_download
from src.delete_payload import handle_delete_payload
from src.repo_manager import add_repo_entry
from backend.config_manager import PAYLOAD_DIR, ALLOWED_EXTENSIONS
from backend.utils import allowed_file, secure_filename

def process_upload_payload(file):
    if not file:
        return {'error': 'No file part'}, 400
    
    if file.filename == '':
        return {'error': 'No selected file'}, 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(PAYLOAD_DIR, filename)

        try:
            file.save(save_path)
            print(f"[UPLOAD] Saved {filename}")
            return {
                'success': True,
                'filename': filename,
                'path': save_path
            }, 200
        except Exception as e:
            return {'error': str(e)}, 500

    return {'error': 'File type not allowed'}, 400

def process_download_payload_url(data):
    url = data.get('url')
    if not url:
        return {'error': 'No URL provided'}, 400

    print(f"[DOWNLOAD] Fetching from {url}...")
    try:
        response, status_code = handle_url_download(url, PAYLOAD_DIR, ALLOWED_EXTENSIONS)
        
        if status_code == 200:
            filename = response.get('filename')
            if filename:
                entry = {
                    "type": "direct",
                    "url": url,
                    "save_path": f"payloads/{filename}"
                }
                add_repo_entry(filename, entry)
        
        return response, status_code
    except Exception as e:
        return {'error': str(e)}, 500

def process_delete_payload(data):
    print(f"[DELETE] Request: {data}")
    try:
        response, status_code = handle_delete_payload(data, PAYLOAD_DIR, ALLOWED_EXTENSIONS)
        return response, status_code
    except Exception as e:
        return {
            'error': str(e),
            'message': 'Failed to delete file'
        }, 500
