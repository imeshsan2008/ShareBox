import os
import json
import subprocess
import threading
import socket
import re
import sys
import webbrowser
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PyQt5.QtGui import QIcon , QCursor
from flask import Flask, request, jsonify,  render_template,render_template_string
from flask_cors import CORS
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import time


app = Flask(__name__)
CORS(app)

DATA_FILE = 'data.json'
CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW
soft_FOLDER = os.path.join(app.static_folder, 'asset')


default_settings = {
    "ssid": "ShareBox",
    "password": "12345678",
    "ftp_user": "user",
    "ftp_pass": "12345",
    "ftp_path": "#",
    "perm":"elradfmwMT"                                                                                                                                                                                                                            
}

default_data = {
    
  "devices": [],
  "next_id": 1

}
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w") as f:
        json.dump(default_data, f, indent=4)
    print("data.json created.")
else:
    print("data.json already exists.")

    
if not os.path.exists("settings.json"):
    with open("settings.json", "w") as f:
        json.dump(default_settings, f, indent=4)
    print("settings.json created.")
else:
    print("settings.json already exists.")
try:
    with open('settings.json', 'r') as f:
        settings = json.load(f)
    ssid = settings.get('ssid', 'ShareBox')
    ftp_user = settings.get('ftp_user', 'user')
    ftp_pass = settings.get('ftp_pass', '123456')
    ftp_path = settings.get('ftp_path', '#')
    perm = settings.get('perm', 'elradfmwMT') 
    
except (FileNotFoundError, json.JSONDecodeError):
    ssid = "ShareBox"
    ftp_user = "user"
    ftp_pass = "12345"
    ftp_path = "#"
    perm = "elradfmwMT"

# SHARED_FOLDER = os.path.abspath(ftp_path)
ftp_server = None
ftp_thread = None 
print(perm)
# ---------- Ftp Server Functions ----------
def get_local_ips():
    hostname = socket.gethostname()
    ips = socket.gethostbyname_ex(hostname)[2]  # Returns all IPs
    return ips


def start_ftp_server(ftp_path):
    global ftp_server
    

    authorizer = DummyAuthorizer()
    authorizer.add_user(ftp_user, ftp_pass, ftp_path, perm=perm)

    handler = CustomFTPHandler
    handler.authorizer = authorizer

    ftp_server = FTPServer(('0.0.0.0', 21), handler)
    ip, port = ftp_server.address
    print(f"Configured to listen on: {ip}:{port}")

    # Start server in background
    thread = threading.Thread(target=ftp_server.serve_forever)
    thread.daemon = True
    thread.start()

    return f"FTP server started successfully with shared folder: {ftp_path}"

class CustomFTPHandler(FTPHandler):
    active_connections = 0

    def on_connect(self):
        CustomFTPHandler.active_connections += 1
        print(f"[FTP] Connected. Active connections: {CustomFTPHandler.active_connections}")
        super().on_connect()

    def on_disconnect(self):
        CustomFTPHandler.active_connections -= 1
        print(f"[FTP] Disconnected. Active connections: {CustomFTPHandler.active_connections}")
        super().on_disconnect()

def stop_ftp_server():
    global ftp_server
    if ftp_server:
        ftp_server.close_all()  # Gracefully stop all connections
        ftp_server = None

# ---------- Helper Functions ----------



def allow_ftp_firewall():
    try:
        rule_name = "Allow FTP Port 21"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=" + rule_name,
            "dir=in",
            "action=allow",
            "protocol=TCP",
            "localport=21"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True,    creationflags=CREATE_NO_WINDOW)
        
        if "Ok." in result.stdout:
            print(f"[✔] Firewall rule added: {rule_name}")
        elif "An object with the same name already exists" in result.stdout:
            print(f"[!] Rule already exists: {rule_name}")
        else:
            print(f"[!] Unexpected output:\n{result.stdout}\n{result.stderr}")

    except Exception as e:
        print(f"[✘] Error adding firewall rule: {e}")

  


def load_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w') as f:
            json.dump({'devices': [], 'next_id': []}, f)
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def get_connected_devices():
    result = subprocess.run(
    ['netsh', 'wlan', 'show', 'hostednetwork'],
    capture_output=True, text=True,
    creationflags=CREATE_NO_WINDOW
)
    macs = re.findall(r'(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))', result.stdout)
    mac_list = [mac[0].replace('-', '').replace(':', '').upper() for mac in macs]

    arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True,    creationflags=CREATE_NO_WINDOW
)
    ip_mac_map = []
    for line in arp_result.stdout.splitlines():
        match = re.match(r'\s*([\d\.]+)\s+([a-fA-F0-9\-]+)\s+dynamic', line)
        if match:
            ip, mac = match.groups()
            mac = mac.replace('-', '').upper()
            ip_mac_map.append({'ip': ip, 'mac': mac})

    connected = []
    for entry in ip_mac_map:
        if entry['mac'] in mac_list:
            connected.append(entry)

    return connected

    
# ---------- Routes ----------



@app.route('/')
def index():
    return render_template('index.html')
@app.route("/devices", methods=["GET"])
def get_devices():
    data = load_data()
    return jsonify(data['devices'])

@app.route("/devices", methods=["POST"])
def add_device():
    payload = request.json
    data = load_data()

    # Ensure `devices` and `next_id` exist
    if 'devices' not in data:
        data['devices'] = []
    if 'next_id' not in data:
        data['next_id'] = 1

    # Check for duplicates by IP
    if not any(d['ip'] == payload['ip'] for d in data['devices']):
        new_device = {
            "id": data['next_id'],
            "ip": payload['ip'],
            "name": payload['name'],
        }
        data['devices'].append(new_device)
        data['next_id'] += 1  # Increment ID
        save_data(data)
        return jsonify({"status": "added", "device": new_device})
    else:
        return jsonify({"status": "duplicate", "message": "IP already exists"})



@app.route("/devices/<ip>", methods=["DELETE"])
def delete_device(ip):
    data = load_data()

    original_length = len(data['devices'])
    data['devices'] = [d for d in data['devices'] if d['ip'] != ip]

    if len(data['devices']) < original_length:
        # Decrease next_id only if a device was actually removed
        if 'next_id' in data and data['next_id'] > 1:
            data['next_id'] -= 1
        save_data(data)
        return jsonify({"status": "deleted", "next_id": data['next_id']})
    else:
        return jsonify({"status": "not found", "message": "Device not found"})

@app.route("/shared")
def list_shared():
    files = os.listdir(ftp_path)
    return jsonify(files)

@app.route('/ftp/stop', methods=['GET'])
def stop_ftp():
    global ftp_server
    if ftp_server:
        stop_ftp_server()
        return jsonify({"status": "FTP server stopped"}), 200
    else:
        return jsonify({"status": "FTP already stopped"}), 200

@app.route('/ftp/start', methods=['GET'])
def start_ftp():
    global ftp_server, ftp_path
    
    # Get the FTP path from query parameters or use a default
    ftp_path = request.args.get('folder_path', './shared') 
    
    print(ftp_path)
    if ftp_server is None:
        try:
            u = start_ftp_server(ftp_path)
            return jsonify({"status": True, "message": u}), 200
        except Exception as e:
            return jsonify({"status": False, "message": str(e)}), 500
    else:
        return jsonify({"status": True, "message": "FTP server already running!", "path": ftp_path}), 200



@app.route('/update_settings', methods=['POST'])
def update_settings():
    data = request.json
    try:
        with open('settings.json', 'w') as f:
            json.dump({"ssid": data['ssid'], "password": data['password'], "ftp_user": data['ftp_user'], "ftp_pass": data['ftp_pass'], "ftp_path": data['ftp_path'],"perm": data['perm']}, f)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


def get_connected_clients_count():
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "hostednetwork", "clients"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode != 0:
            return result.stderr
            
        output = result.stdout
        count = 0
        
        # Find the line with "Number of clients"
        for line in output.split('\n'):
            if "Number of clients" in line:
                count = int(line.split(':')[-1].strip())
                break
                
        return count
        
    except Exception as e:
        return  str(e)


@app.route("/status")
def wifi_status():
    try:
        with open('settings.json', 'r') as f:
            settings = json.load(f)
        ssid = settings.get('ssid', 'ShareBox')
        password = settings.get('password', '12345678')
        ftp_user = settings.get('ftp_user', 'user')
        ftp_pass = settings.get('ftp_pass', '12345')
        ftp_path = settings.get('ftp_path', '#')
        perm = settings.get('perm', 'elradfmwMT')
    except (FileNotFoundError, json.JSONDecodeError):
        ssid = "ShareBox"
        password = "12345678"
        ftp_user = "user"
        ftp_pass = "12345"
        ftp_path = "#"
        perm = "elradfmwMT"

    if ftp_server is None:
        ftp_status = False
        active_connections = 0
    else:
        ftp_status = True
        active_connections = CustomFTPHandler.active_connections

    result = subprocess.getoutput("netsh wlan show hostednetwork")
    
    data = load_data()
    next_id = data['next_id']  
    return jsonify({
        "status_hostpot": result,
        "active_connections": active_connections,
        "anonymous_allowed": True,
        "next_id": next_id,
        "ssid": ssid,
        "password": password,
        "ftp_user": ftp_user,
        "ftp_pass": ftp_pass,
        "ftp_path": ftp_path,
        "ftp_status": ftp_status,
        "perm": perm,
        "server_address": get_local_ips(),
        "hostpot_con_cou": get_connected_clients_count()
    })


@app.route("/start_hotspot", methods=["POST"])
def start_hotspot():
    key = request.json.get("password", "12345678")
    subprocess.run(["netsh", "wlan", "set", "hostednetwork", "mode=allow", f"ssid={ssid}", f"key={key}"],    creationflags=CREATE_NO_WINDOW)
    subprocess.run(["netsh", "wlan", "start", "hostednetwork"],    creationflags=CREATE_NO_WINDOW)
    return jsonify({"status": "Hotspot started"})

@app.route("/stop_hotspot", methods=["POST"])
def stop_hotspot():
    subprocess.run(["netsh", "wlan", "stop", "hostednetwork"],    creationflags=CREATE_NO_WINDOW)
    return jsonify({"status": "Hotspot stopped"})


@app.route('/open-device/<device_name>', methods=['GET'])
def open_device(device_name):
    unc_path = f"\\\\{device_name}\\"

    try:
        result = subprocess.run(["net", "view", unc_path],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                shell=True,    creationflags=CREATE_NO_WINDOW)  

        if result.returncode != 0:
            return jsonify({
                "status": "error",
                "message": f"Device '{device_name}' not found or no shared drives available."
            }), 404
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to check network share: {str(e)}"
        }), 500

    try:
        subprocess.Popen(["explorer", unc_path], shell=True)
        return jsonify({
            "status": "success",
            "message": f"Opened {unc_path} in File Explorer"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to open path in Explorer: {str(e)}"
        }), 500

#----------- ui 
IS_FROZEN = getattr(sys, 'frozen', False)
@app.route('/ftpservers')
def list_softwear():
    try:
        files = os.listdir(soft_FOLDER)
        files = [f for f in files if os.path.isfile(os.path.join(soft_FOLDER, f))]
    except FileNotFoundError:
        files = []

    # Render a directory-like view
    return render_template_string('''
    <h2>Ftp Software</h2>
    <ul>
    {% for file in files %}
      <li><a href="{{ url_for('static', filename='asset/' + file) }}" download>{{ file }}</a></li>
    {% endfor %}
    </ul>
    ''', files=files)

def openweb():
    time.sleep(3)
    webbrowser.open('http://127.0.0.1:5000/')

def run_flask():
    debug_mode = not IS_FROZEN  # True in dev, False in exe
    openweb()
    if not sys.platform.startswith("win"):
        print("This script is for Windows only.")
    else:
        
        allow_ftp_firewall()

    app.run(host='0.0.0.0', port=5000, debug=debug_mode, use_reloader=False)

def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    tray = QSystemTrayIcon()
    tray.setIcon(QIcon("icon.png"))

    menu = QMenu()
    action2 = menu.addAction("Open Web Page")
    quit_action = menu.addAction("Quit")

    action2.triggered.connect(openweb)
    quit_action.triggered.connect(app.quit)

    tray.setContextMenu(menu)
    
    # Show menu on left-click
    tray.activated.connect(lambda reason: menu.popup(QCursor.pos()) if reason == QSystemTrayIcon.Trigger else None)
    
    tray.show()

    sys.exit(app.exec_())
    
if __name__ == '__main__':
    try:
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()

        main()
        openweb()
    except KeyboardInterrupt:
        print("Shutting down gracefully...")
        sys.exit(0)