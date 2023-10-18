from flask import Flask, render_template, request, jsonify
import socket
from concurrent.futures import ThreadPoolExecutor
from pymongo import MongoClient

app = Flask(__name__)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["portscanner_database"]
collection = db["scan_results"]

IMPORTANT_PORTS = [21, 22, 25, 53, 80, 443]  # Modify this list as needed

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    start_port = int(request.form.get('startPort', 1))
    end_port = int(request.form.get('endPort', 1024))
    open_ports_details = main(target, ports=range(start_port, end_port + 1))
    
    os_guess = guess_os(open_ports_details)

    # Store results in MongoDB
    collection.insert_one({
        "domain": target,
        "os_guess": os_guess,
        "results": open_ports_details
    })

    return jsonify({
        "os_guess": os_guess,
        "open_ports_details": open_ports_details
    })



def get_service_name(port):
    try:
        name = socket.getservbyport(port)
        return name
    except:
        return None

def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            s.connect((target, port))
            service_name = get_service_name(port)
            state = "open"
            return port, state, service_name
    except:
        if port in IMPORTANT_PORTS:
            state = "closed"
            return port, state, None
        return None, None, None  # Skip other ports

def guess_os(open_ports_details):
    os_guess = "Unknown"
    
    # Check for Windows specific ports
    if any(detail["port"] == "137/tcp" for detail in open_ports_details):
        os_guess = "Windows"
    # Check for common Linux ports
    elif any(detail["port"] == "22/tcp" for detail in open_ports_details):
        os_guess = "Linux/Unix"
    
    elif any(detail["port"] in ["548/tcp", "631/tcp"] for detail in open_ports_details):
        os_guess = "Mac OS X"


    return os_guess

def main(target, ports=range(1, 1025)):
    open_ports_details = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, target, port) for port in ports]
        
        for future in futures:
            port, state, service = future.result()
            if port and state:  # Only consider open ports or "important" closed ones
                port_info = {
                    "port": f"{port}/tcp",
                    "state": state,
                    "service": service if service else "unknown"
                }
                open_ports_details.append(port_info)
    
    return open_ports_details

if __name__ == '__main__':
    app.run(debug=True)
