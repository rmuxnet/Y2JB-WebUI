import os
import json
from src.repo_manager import update_payloads, add_repo_entry, delete_repo_entry

REPO_FILE = os.path.join("static", "config", "repos.json")

def get_repo_keys():
    try:
        with open(REPO_FILE, 'r') as f:
            repos = json.load(f)
        return list(repos.keys())
    except:
        return []

def get_all_repos():
    try:
        with open(REPO_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def process_repo_update(targets):
    print(f"[REPO] Updating targets: {targets}")
    return update_payloads(targets)

def process_add_repo(data):
    name = data.get('name')
    old_name = data.get('old_name')

    if not name: 
        return {"error": "Missing name"}, 400
    
    if old_name and old_name != name:
        delete_repo_entry(old_name)

    config_data = {k:v for k,v in data.items() if k not in ['name', 'old_name']}
    add_repo_entry(name, config_data)
    return {"success": True}, 200

def process_delete_repo(name):
    try:
        delete_repo_entry(name)
        return {"success": True}, 200
    except Exception as e:
        return {"error": str(e)}, 500
