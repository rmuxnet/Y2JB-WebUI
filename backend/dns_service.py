import uuid
from backend.config_manager import get_dns_rules, save_dns_rules

def get_all_rules():
    return get_dns_rules()

def process_add_dns_rule(data):
    name = data.get('name')
    domain = data.get('domain')
    target = data.get('target', '0.0.0.0')

    if not name or not domain:
        return {"error": "Name and Domain are required"}, 400, False

    try:
        rules = get_dns_rules()
        new_rule = {
            "id": str(uuid.uuid4()),
            "name": name,
            "domain": domain,
            "target": target
        }
        rules.append(new_rule)
        save_dns_rules(rules)
        return {"success": True}, 200, True
    except Exception as e:
        return {"error": str(e)}, 500, False

def process_delete_dns_rule(data):
    rule_id = data.get('id')
    try:
        rules = get_dns_rules()
        original_count = len(rules)
        rules = [r for r in rules if r.get('id') != rule_id]
        
        save_dns_rules(rules)
        return {"success": True}, 200, True
    except Exception as e:
        return {"error": str(e)}, 500, False
