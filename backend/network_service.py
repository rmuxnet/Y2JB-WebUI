import socket

def get_local_ip(target_ip="8.8.8.8"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_network_info(client_ip):
    server_ip = get_local_ip()
    return {
        "server_ip": server_ip,
        "client_ip": client_ip
    }
