import os
import json

PAYLOAD_DIR = "payloads"
DAT_DIR = "payloads/dat"
CONFIG_DIR = "static/config"
CONFIG_FILE = os.path.join(CONFIG_DIR, "settings.json")
PAYLOAD_CONFIG_FILE = os.path.join(CONFIG_DIR, "payload_config.json")
PAYLOAD_ORDER_FILE = os.path.join(CONFIG_DIR, "payload_order.json")
PAYLOAD_DELAYS_FILE = os.path.join(CONFIG_DIR, "payload_delays.json")
PAYLOAD_DELAY_FLAGS_FILE = os.path.join(CONFIG_DIR, "payload_delay_flags.json")
DNS_CONFIG_FILE = os.path.join(CONFIG_DIR, "dns_rules.json")
ALLOWED_EXTENSIONS = {'bin', 'elf', 'js', 'dat'}

def ensure_directories():
    os.makedirs(PAYLOAD_DIR, exist_ok=True)
    os.makedirs(DAT_DIR, exist_ok=True)
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs('templates', exist_ok=True)

    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w') as f:
            json.dump({"ajb": "false", "ip": ""}, f)

def get_payload_config():
    if not os.path.exists(PAYLOAD_CONFIG_FILE):
        return {}
    try:
        with open(PAYLOAD_CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_payload_config(config):
    with open(PAYLOAD_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def get_payload_order():
    if not os.path.exists(PAYLOAD_ORDER_FILE):
        return []
    try:
        with open(PAYLOAD_ORDER_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def save_payload_order(order):
    with open(PAYLOAD_ORDER_FILE, 'w') as f:
        json.dump(order, f, indent=4)

def get_payload_delays():
    if not os.path.exists(PAYLOAD_DELAYS_FILE):
        return {}
    try:
        with open(PAYLOAD_DELAYS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_payload_delays(data):
    with open(PAYLOAD_DELAYS_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def get_payload_delay_flags():
    if not os.path.exists(PAYLOAD_DELAY_FLAGS_FILE):
        return {}
    try:
        with open(PAYLOAD_DELAY_FLAGS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_payload_delay_flags(flags):
    with open(PAYLOAD_DELAY_FLAGS_FILE, 'w') as f:
        json.dump(flags, f, indent=4)

def get_config():
    if not os.path.exists(CONFIG_FILE):
        return {"ajb": "false", "ip": ""}
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {"ajb": "false", "ip": ""}

def update_config(key, value):
    config = get_config()
    config[key] = str(value)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def get_dns_rules():
    if not os.path.exists(DNS_CONFIG_FILE):
        return []
    try:
        with open(DNS_CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def save_dns_rules(rules):
    with open(DNS_CONFIG_FILE, 'w') as f:
        json.dump(rules, f, indent=4)
