import os
import time
import fnmatch
import logging
from backend.config_manager import (
    PAYLOAD_DIR, 
    get_payload_order, 
    get_payload_delay_flags, 
    get_payload_config, 
    get_config
)
from src.SendPayload import send_payload

def get_sorted_payloads():
    payload_files = []
    try:
        for root, dirs, files in os.walk(PAYLOAD_DIR):
            for file in files:
                if file.lower().endswith(('.bin', '.elf', '.js', '.dat')):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, PAYLOAD_DIR)
                    rel_path = rel_path.replace("\\", "/") 
                    payload_files.append(rel_path)
        
        order = get_payload_order()
        weights = {name: i for i, name in enumerate(order)}
        payload_files.sort(key=lambda x: weights.get(x, 9999))
        
        return payload_files
    except Exception as e:
        print(f"[ERROR] listing payloads: {e}")
        return []

def run_auto_jailbreak(host):
    print("--- Starting Auto-Jailbreak Sequence ---")
    config = get_payload_config()

    print(f"[SEND] lapse.js -> {host}:50000")
    result = send_payload(file_path='payloads/js/lapse.js', host=host, port=50000)
    time.sleep(10)
    
    if not result:
        return False, "Failed to send lapse.js"

    global_config = get_config()
    kstuff_enabled = global_config.get("kstuff", "true") == "true"
    kstuff_result = True 

    if kstuff_enabled:
        print(f"[SEND] kstuff.elf -> {host}:9021")
        kstuff_result = send_payload(file_path='payloads/kstuff.elf', host=host, port=9021)
        time.sleep(10)
    else:
        print("[SKIP] kstuff.elf (Disabled in Settings)")
    
    if not kstuff_result:
        return False, "Failed to send kstuff.elf"

    files = os.listdir(PAYLOAD_DIR)
    try:
        order = get_payload_order()
        weights = {name: i for i, name in enumerate(order)}
        files.sort(key=lambda x: weights.get(x, 9999))
    except Exception as e:
        print(f"[SORT] Error sorting payloads: {e}")

    delay_flags = get_payload_delay_flags()
    
    try:
        delay_time = float(global_config.get("global_delay", "5"))
    except:
        delay_time = 5.0

    for filename in files:
        if not config.get(filename, True):
            print(f"[SKIP] {filename} (Disabled in settings)")
            continue

        if (fnmatch.fnmatch(filename, '*.bin') or fnmatch.fnmatch(filename, '*.elf')) and filename != 'kstuff.elf':
            print(f"[SEND] {filename} -> {host}:9021")
            result = send_payload(file_path=os.path.join(PAYLOAD_DIR, filename), host=host, port=9021)
            
            if delay_flags.get(filename, False):
                print(f"[WAIT] Sleeping {delay_time}s for {filename}...")
                time.sleep(delay_time)
            else:
                time.sleep(0.5)
            
            if not result:
                print(f"[FAIL] Could not send {filename}")
                return False, f"Failed to send {filename}"
    
    print("--- Auto-Jailbreak Sequence Complete ---")
    return True, "All payloads sent successfully"

def process_manual_payload(host, payload_path):
    port = 9021
    if payload_path.lower().endswith('.js'):
        port = 50000
    
    print(f"[MANUAL] Sending {payload_path} -> {host}:{port}")
    result = send_payload(file_path=payload_path, host=host, port=port)
    
    if result:
        return True, "Custom payload sent"
    else:
        return False, "Failed to send custom payload"
