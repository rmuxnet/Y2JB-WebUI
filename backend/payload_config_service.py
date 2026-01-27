from backend.config_manager import (
    get_payload_config, save_payload_config,
    get_payload_order, save_payload_order,
    get_payload_delays, save_payload_delays,
    get_payload_delay_flags, save_payload_delay_flags
)

def process_toggle_payload_config(data):
    filename = data.get('filename')
    enabled = data.get('enabled')
    
    if not filename:
        return {"error": "Missing filename"}, 400
        
    config = get_payload_config()
    config[filename] = enabled
    save_payload_config(config)
    
    return {"success": True}, 200

def process_save_payload_order(order):
    try:
        save_payload_order(order)
        return {"success": True}, 200
    except Exception as e:
        return {"error": str(e)}, 500

def process_save_payload_delay(data):
    filename = data.get('filename')
    delay = data.get('delay')
    
    if not filename:
        return {"error": "Missing filename"}, 400
    
    delays = get_payload_delays()
    if delay is None or delay == "":
        if filename in delays:
            del delays[filename]
    else:
        delays[filename] = int(delay)
        
    save_payload_delays(delays)
    return {"success": True}, 200

def process_toggle_payload_delay_flag(data):
    filename = data.get('filename')
    enabled = data.get('enabled')
    
    if not filename:
        return {"error": "Missing filename"}, 400
        
    flags = get_payload_delay_flags()
    flags[filename] = enabled
    save_payload_delay_flags(flags)
    
    return {"success": True}, 200
