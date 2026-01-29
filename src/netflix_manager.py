import subprocess
import os
import sys
import re
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class NetflixManager:
    def __init__(self, root_dir):
        self.root_dir = Path(root_dir)
        self.hack_dir = self.root_dir / "netflix_hack"
        self.proxy_process = None
        self.ws_process = None

    def get_status(self):
        return {
            "proxy": self.proxy_process is not None and self.proxy_process.poll() is None,
            "websocket": self.ws_process is not None and self.ws_process.poll() is None
        }

    def update_config(self, ip_address, port):
        target_file = "inject_elfldr_automated.js"
        
        ip_pattern = r'(const ip_script = ")(.*?)(";)'
        port_pattern = r'(const ip_script_port = )(\d+)(;)'

        try:
            if not self.hack_dir.exists():
                return False, "netflix_hack directory not found."

            file_path = self.hack_dir / target_file
            if not file_path.exists():
                return False, f"{target_file} not found in netflix_hack/"

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            content = re.sub(ip_pattern, f'\\g<1>{ip_address}\\g<3>', content)
            content = re.sub(port_pattern, f'\\g<1>{port}\\g<3>', content)

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True, f"Configuration updated to {ip_address}:{port}"
        except Exception as e:
            return False, str(e)

    def generate_certs(self):
        try:
            if not self.hack_dir.exists():
                os.makedirs(self.hack_dir)

            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
            )

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            ).sign(key, hashes.SHA256())

            key_path = self.hack_dir / "key.pem"
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            cert_path = self.hack_dir / "cert.pem"
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            return True, "Certificates generated successfully."

        except Exception as e:
            return False, f"Certificate Generation Failed: {str(e)}"

    def start_services(self):
        if self.get_status()["proxy"]:
            return False, "Services are already running."

        if not (self.hack_dir / "payloads").exists():
             return False, "Error: 'payloads' folder missing inside netflix_hack/"

        if not (self.hack_dir / "key.pem").exists():
            return False, "Certificates missing. Please generate them first."

        try:
            self.ws_process = subprocess.Popen(
                [sys.executable, "ws.py"],
                cwd=self.hack_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            self.proxy_process = subprocess.Popen(
                ["mitmdump", "-s", "proxy.py"],
                cwd=self.hack_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return True, "Proxy and WebSocket servers started."
        except Exception as e:
            self.stop_services()
            return False, f"Failed to start services: {str(e)}"

    def stop_services(self):
        msg = []
        if self.ws_process:
            self.ws_process.terminate()
            self.ws_process = None
            msg.append("WebSocket")
        
        if self.proxy_process:
            self.proxy_process.terminate()
            self.proxy_process = None
            msg.append("Proxy")
            
        return True, f"Stopped: {', '.join(msg)}" if msg else "No services were running."