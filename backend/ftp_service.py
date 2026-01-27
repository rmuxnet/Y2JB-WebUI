import os
import io
from flask import send_file
from src.ftp_manager import (
    list_ftp_directory, 
    delete_item, 
    create_directory, 
    rename_item, 
    download_file_content, 
    upload_file_content
)
from backend.config_manager import get_config
from backend.utils import secure_filename

def get_ftp_connection_info():
    config = get_config()
    ip = config.get("ip")
    port = config.get("ftp_port", "1337")
    return ip, port

def process_ftp_list(path):
    ip, port = get_ftp_connection_info()
    if not ip:
        return {"success": False, "error": "IP not configured"}, 400
        
    result = list_ftp_directory(ip, port, path)
    if result['success']:
        return result, 200
    else:
        return result, 500

def process_ftp_download(path, as_text=False):
    ip, port = get_ftp_connection_info()
    
    result = download_file_content(ip, port, path)
    if not result['success']:
        return result, 500

    if as_text:
        try:
            return {"success": True, "content": result['content'].decode('utf-8')}, 200
        except:
            return {"success": False, "error": "Could not decode file as text"}, 200
    
    filename = os.path.basename(path)
    return send_file(
        io.BytesIO(result['content']),
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )

def process_ftp_upload(path, file, text_content):
    ip, port = get_ftp_connection_info()
    
    if text_content is not None:
        result = upload_file_content(ip, port, path, text_content.encode('utf-8'))
        return result

    if file:
        file_content = file.read()
        filename = secure_filename(file.filename)
        full_path = f"{path.rstrip('/')}/{filename}"
        result = upload_file_content(ip, port, full_path, file_content)
        return result
        
    return {"success": False, "error": "No data provided"}

def process_ftp_action(action, path, data):
    ip, port = get_ftp_connection_info()
    
    if action == 'delete':
        return delete_item(ip, port, path, data.get('is_dir', False))
    elif action == 'mkdir':
        return create_directory(ip, port, path)
    elif action == 'rename':
        return rename_item(ip, port, path, data.get('new_path'))
        
    return {"success": False, "error": "Invalid action"}
