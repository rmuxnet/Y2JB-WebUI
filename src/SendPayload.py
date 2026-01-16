import socket
import sys
import time

def send_payload(file_path, host, port=50000, tries=5):
    attempt = 0
    while attempt < tries:
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            print(f"Connecting to {host}:{port}...")
            sock.connect((host, port))
            
            print(f"Sending file {file_path} ({len(data)} bytes)...")
            sock.sendall(data)
            
            sock.close()
            
            time.sleep(0.5)
            
            print('done')
            return True
            
        except ConnectionRefusedError:
            print(f"Connection refused: {host}:{port}")
        except socket.gaierror:
            print(f"Host doesn't exist: {host}")
        except socket.timeout:
            print(f"Connection timeout: {host}:{port}")
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return False
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
        
        attempt += 1
        if attempt < tries:
            print(f"Attempt {attempt} failed, retrying...")
            time.sleep(1)
    
    print(f"Failed after {tries} attempts")
    return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("""
Payload Sender - Usage:
  python SendPayload.py <host> <file> [port] [tries]

Examples:
  python SendPayload.py 192.168.1.123 lapse.js 50000
  python SendPayload.py 192.168.1.123 etahen.bin 9021

Note: Make sure the target server is listening on the specified port
""")
        sys.exit(1)

    host = sys.argv[1]
    file_path = sys.argv[2]

    if len(sys.argv) > 3:
        port = int(sys.argv[3])
    else:
        port = 50000

    print(f"Starting transmission to {host}:{port}")

    if send_payload(file_path, host, port):
        print("Transmission completed successfully")
        sys.exit(0)
    else:
        print("Transmission failed")
        sys.exit(1)
