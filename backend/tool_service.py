from backend.config_manager import get_config
from src.ps5_utils import auto_replace_download0, patch_blocker

def process_update_download0():
    config = get_config()
    ip = config.get("ip")
    port = config.get("ftp_port", "1337")
    
    if not ip:
        return {"success": False, "message": "IP Address not set"}, 400

    print(f"[TOOL] Installing download0.dat to {ip}...")
    success, message = auto_replace_download0(ip, port)
    
    if success:
        return {"success": True, "message": message}, 200
    else:
        return {"success": False, "message": message}, 500

def process_block_updates():
    config = get_config()
    ip = config.get("ip")
    port = config.get("ftp_port", "1337")
    
    if not ip:
        return {"success": False, "message": "IP Address not set"}, 400

    print(f"[TOOL] Blocking updates on {ip}...")
    success, message = patch_blocker(ip, port)
    if success:
        return {"success": True, "message": message}, 200
    else:
        return {"success": False, "message": message}, 500
