import json
from backend.config_manager import get_config, update_config, CONFIG_FILE

def process_update_settings(new_settings):
    try:
        current_config = get_config()
        
        valid_keys = [
            'ip', 'ajb', 'ftp_port', 'global_delay', 
            'ui_animations', 'kstuff', 'debug_mode', 
            'auto_update_repos', 'dns_auto_start', 'compact_mode'
        ]
        for key in valid_keys:
            if key in new_settings:
                current_config[key] = str(new_settings[key])
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(current_config, f, indent=4)
            
        return {"success": True, "message": "Settings saved successfully"}, 200
    except Exception as e:
        return {"success": False, "error": str(e)}, 500

def process_update_single_setting(key, value):
    try:
        update_config(key, value)
        return "Settings updated!", 200
    except Exception as e:
        return str(e), 500
