from flask import Flask, render_template, request, jsonify
import socket
from concurrent.futures import ThreadPoolExecutor
from pymongo import MongoClient

app = Flask(__name__)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["portscanner_database"]
collection = db["scan_results"]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    open_ports_details = main(target)

    # Store results in MongoDB
    collection.insert_one({
        "domain": target,
        "results": open_ports_details
    })

    return jsonify({"open_ports_details": open_ports_details})

def get_service_name(port):
    try:
        name = socket.getservbyport(port)
        return name
    except:
        return None

def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((target, port))
            service_name = get_service_name(port)
            state = "open"
            return port, state, service_name
    except:
        state = "closed"
        return port, state, None

def main(target, ports=range(1, 1025)):
    open_ports_details = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, target, port) for port in ports]
        
        for future in futures:
            port, state, service = future.result()
            if state == "open":
                port_info = {
                    "port": f"{port}/tcp",
                    "state": state,
                    "service": service if service else "unknown"
                }
                open_ports_details.append(port_info)
    
    return open_ports_details

if __name__ == '__main__':
    app.run(debug=True)