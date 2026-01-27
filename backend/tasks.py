import time
import requests
from backend.config_manager import get_config

def check_ajb(endpoint_url):
    while True:
        try:
            config = get_config()
            ajb_content = config.get("ajb", "false").lower()

            if ajb_content == "true":
                ip_address = config.get("ip", "").strip()

                if not ip_address:
                    print("[AJB] Enabled but IP missing")
                else:
                    response = requests.post(endpoint_url, json={
                        "IP": ip_address,
                        "payload": ""
                    })

                    if response.status_code == 200:
                        print("[AJB] Sequence completed successfully")
                    else:
                        print(f"[AJB] Error: {response.text}")

        except Exception as e:
            print("[AJB] Error:", str(e))

        finally:
            time.sleep(5)
