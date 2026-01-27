from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
import threading
from src.dns_server import DNSServer
from src.features import setup_logging, run_startup_tasks
from backend.config_manager import (
    ensure_directories, 
    get_config, 
    update_config, 
    DNS_CONFIG_FILE,
    get_payload_config,
    get_payload_order,
    get_payload_delays,
    get_payload_delay_flags
)
from backend.tasks import check_ajb
from backend.payload_service import get_sorted_payloads, run_auto_jailbreak, process_manual_payload
from backend.ftp_service import (
    process_ftp_list, 
    process_ftp_download, 
    process_ftp_upload, 
    process_ftp_action
)
from backend.repo_service import (
    get_repo_keys,
    get_all_repos,
    process_repo_update,
    process_add_repo,
    process_delete_repo
)
from backend.dns_service import (
    get_all_rules,
    process_add_dns_rule,
    process_delete_dns_rule
)
from backend.tool_service import process_update_download0, process_block_updates
from backend.settings_service import process_update_settings, process_update_single_setting
from backend.payload_config_service import (
    process_toggle_payload_config,
    process_save_payload_order,
    process_save_payload_delay,
    process_toggle_payload_delay_flag
)
from backend.payload_file_service import (
    process_upload_payload,
    process_download_payload_url,
    process_delete_payload
)
from backend.backpork_service import (
    get_backpork_pairs,
    get_backpork_config,
    save_backpork_config,
    run_backpork_stream
)
from backend.network_service import get_network_info, get_local_ip

app = Flask(__name__)
app.secret_key = 'Nazky'
CORS(app)

dns_service = None
url = "http://localhost:8000/send_payload"

ensure_directories()

@app.route("/")
def home():
    return render_template('index.html')

@app.route('/api/payload_config', methods=['GET'])
def get_payload_config_route():
    return jsonify(get_payload_config())

@app.route('/api/payload_config/toggle', methods=['POST'])
def toggle_payload_config():
    try:
        response, status = process_toggle_payload_config(request.json)
        return jsonify(response), status
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/payload_order', methods=['GET', 'POST'])
def handle_payload_order():
    if request.method == 'GET':
        return jsonify(get_payload_order())
    
    if request.method == 'POST':
        response, status = process_save_payload_order(request.json.get('order', []))
        return jsonify(response), status

@app.route('/api/payload_delay', methods=['GET', 'POST'])
def handle_payload_delay():
    if request.method == 'GET':
        return jsonify(get_payload_delays())
    
    if request.method == 'POST':
        try:
            response, status = process_save_payload_delay(request.json)
            return jsonify(response), status
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/api/payload_delays', methods=['GET'])
def get_payload_delays_route():
    return jsonify(get_payload_delay_flags())

@app.route('/api/payload_delays/toggle', methods=['POST'])
def toggle_payload_delay_flag():
    try:
        response, status = process_toggle_payload_delay_flag(request.json)
        return jsonify(response), status
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/edit_ajb', methods=['POST'])
def edit_ajb():
    new_content = request.json.get('content')
    return process_update_single_setting("ajb", new_content)

@app.route('/edit_ip', methods=['POST'])
def edit_ip():
    new_content = request.json.get('content')
    return process_update_single_setting("ip", new_content)

@app.route('/list_payloads')
def list_files():
    try:
        payloads = get_sorted_payloads()
        return jsonify(payloads)
    except Exception as e:
        return jsonify({"error": "Folder not found"}), 404

@app.route('/upload_payload', methods=['POST'])
def upload_payload():
    if 'file' not in request.files:
         return jsonify({'error': 'No file part'}), 400
    
    response, status = process_upload_payload(request.files['file'])
    return jsonify(response), status

@app.route('/download_payload_url', methods=['POST'])
def download_payload_url():
    response, status = process_download_payload_url(request.get_json())
    return jsonify(response), status

@app.route("/send_payload", methods=["POST"])
def sending_payload():
    try:
        data = request.get_json()
        host = data.get("IP")
        payload = data.get("payload")

        if not host:
            return jsonify({"error": "Missing IP parameter"}), 400
            
        if not payload:
            success, message = run_auto_jailbreak(host)
            if success:
                return jsonify({"success": True, "message": message})
            else:
                return jsonify({"error": message}), 500
        else:
            success, message = process_manual_payload(host, payload)
            if success:
                return jsonify({"success": True, "message": message})
            else:
                return jsonify({"error": message}), 500

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return jsonify({"error": str(e)}), 500
    
@app.route('/delete_payload', methods=['POST'])
def delete_payload():
    response, status = process_delete_payload(request.get_json())
    return jsonify(response), status

@app.route('/list_repos')
def list_repos():
    return jsonify(get_repo_keys())

@app.route('/update_repos', methods=['POST'])
def update_repos():
    try:
        data = request.get_json() or {}
        targets = data.get('targets', ['all'])
        result = process_repo_update(targets)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/settings/repos')
def repo_manager_ui():
    return render_template('repos.html')

@app.route('/api/repos/list')
def get_repo_list():
    return jsonify(get_all_repos())

@app.route('/api/repos/add', methods=['POST'])
def add_new_repo():
    try:
        data = request.json
        response, status = process_add_repo(data)
        return jsonify(response), status
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/repos/delete', methods=['POST'])
def remove_repo():
    try:
        data = request.json
        name = data.get('name')
        response, status = process_delete_repo(name)
        return jsonify(response), status
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/edit_ftp_port', methods=['POST'])
def edit_ftp_port():
    new_content = request.json.get('content')
    return process_update_single_setting("ftp_port", new_content)

@app.route('/tools/update_download0', methods=['POST'])
def run_update_download0():
    response, status = process_update_download0()
    return jsonify(response), status

@app.route('/tools/block_updates', methods=['POST'])
def run_block_updates():
    response, status = process_block_updates()
    return jsonify(response), status

@app.route('/credits')
def credits_page():
    return render_template('credits.html')

@app.route('/settings')
def settings_page():
    return render_template('settings.html')

@app.route('/api/settings', methods=['GET', 'POST'])
def handle_settings():
    if request.method == 'GET':
        return jsonify(get_config())
    
    if request.method == 'POST':
        response, status = process_update_settings(request.get_json())
        return jsonify(response), status

@app.route('/api/network_info')
def network_info():
    client_ip = request.remote_addr
    return jsonify(get_network_info(client_ip))

@app.route('/ftp')
def ftp_page():
    return render_template('ftp.html')

@app.route('/api/ftp/list', methods=['POST'])
def api_ftp_list():
    path = request.json.get('path', '/')
    response, status_code = process_ftp_list(path)
    return jsonify(response), status_code

@app.route('/api/ftp/download_file', methods=['POST'])
def api_ftp_download():
    path = request.json.get('path')
    as_text = request.json.get('as_text')
    
    result = process_ftp_download(path, as_text)
    
    if isinstance(result, tuple):
         return jsonify(result[0]), result[1]
    
    return result

@app.route('/api/ftp/upload_file', methods=['POST'])
def api_ftp_upload():
    path = request.form.get('path')
    file = request.files.get('file')
    text_content = request.form.get('content')
    
    result = process_ftp_upload(path, file, text_content)
    status = 400 if not result.get('success', True) else 200
    return jsonify(result), status

@app.route('/api/ftp/action', methods=['POST'])
def api_ftp_action():
    data = request.json
    action = data.get('action')
    path = data.get('path')
    
    result = process_ftp_action(action, path, data)
    status = 400 if result.get('error') == "Invalid action" else 200
    
    return jsonify(result), status

@app.route('/dns')
def dns_page():
    return render_template('dns.html')

@app.route('/api/dns/list')
def api_dns_list():
    return jsonify(get_all_rules())

@app.route('/api/dns/add', methods=['POST'])
def api_dns_add():
    response, status, reload_needed = process_add_dns_rule(request.json)
    if reload_needed and dns_service:
        dns_service.load_rules()
    return jsonify(response), status

@app.route('/api/dns/delete', methods=['POST'])
def api_dns_delete():
    response, status, reload_needed = process_delete_dns_rule(request.json)
    if reload_needed and dns_service:
        dns_service.load_rules()
    return jsonify(response), status

@app.route('/backpork')
def backpork_page():
    pairs = get_backpork_pairs()
    return render_template('backpork.html', sdk_pairs=pairs)

@app.route("/api/backpork/settings", methods=['GET', 'POST'])
def handle_backpork_settings():
    if request.method == 'GET':
        return jsonify(get_backpork_config())
    if request.method == 'POST':
        return jsonify(save_backpork_config(request.json))

@app.route("/api/backpork/run", methods=['POST'])
def run_backpork_process():
    data = request.json
    return Response(run_backpork_stream(data), mimetype='text/event-stream')

if __name__ == "__main__":
    config = get_config()
    
    setup_logging(config)
    
    run_startup_tasks(config)

    threading.Thread(target=check_ajb, args=(url,), daemon=True).start()

    local_ip = get_local_ip("1.1.1.1")

    if config.get("dns_auto_start", "true") == "true":
        print(f"--- Initializing DNS Server on {local_ip} ---")
        dns_service = DNSServer(config_file=DNS_CONFIG_FILE, host_ip=local_ip)
        threading.Thread(target=dns_service.start, daemon=True).start()
    else:
        print("[STARTUP] DNS Server disabled by settings")

    app.run(host="0.0.0.0", port=8000, debug=(config.get("debug_mode") == "true"))