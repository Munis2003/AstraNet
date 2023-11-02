from flask import Flask, render_template, request, jsonify
import socket
from concurrent.futures import ThreadPoolExecutor
from pymongo import MongoClient
import whois



app = Flask(__name__)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["astranet_db"]
collection = db["scan_results"]


IMPORTANT_PORTS = [21, 22, 25, 53, 80, 443]  # Modify this list as needed


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/port-scan')
def port_scan():
    return render_template('port_scan.html')


@app.route('/input-validation')
def input_validation():
    return "Input Validation Tool is under development."



@app.route('/whois-lookup', methods=['GET', 'POST'])
def whois_lookup():
    if request.method == 'POST':
        domain = request.form['domain']
        result = perform_whois_lookup(domain)

        # Store the WHOIS data in MongoDB
        if not result.get("error"):
            collection.insert_one({
                "domain": domain,
                "whois_info": result["whois_info"]
            })

        return jsonify(result)
    return render_template('whois_lookup.html')


def perform_whois_lookup(domain):
    try:
        whois_info = whois.whois(domain)
        # Process the WHOIS information as needed
        # You can return the raw WHOIS data or specific details from it
        print(whois_info)
        return {"domain": domain, "whois_info": whois_info}
    except Exception as e:
        return {"error": str(e)}


@app.route('/dns-lookup')
def dns_lookup():
    return render_template('dns_lookup.html')

@app.route('/execute-dns-lookup', methods=['POST'])
def execute_dns_lookup():
    domain = request.form['domain']
    results = perform_dns_lookup(domain)
    return jsonify(results)

def perform_dns_lookup(domain):
    try:
        ip_addresses = socket.getaddrinfo(domain, None)
        addresses = [info[4][0] for info in ip_addresses]
        return {"domain": domain, "addresses": addresses}
    except Exception as e:
        return {"error": str(e)}
    
@app.route('/reverse-dns', methods=['POST'])
def reverse_dns():
    ip_address = request.form['ip_address']
    try:
        host_name, _, _ = socket.gethostbyaddr(ip_address)
        return jsonify({
            "success": True,
            "hostname": host_name
        })
    except socket.herror:  # Handle error where no PTR record exists
        return jsonify({
            "success": False,
            "message": "No PTR record found for IP: " + ip_address
        }), 400


@app.route('/directory-enumeration')
def directory_enumeration():
    return "Directory Enumeration Tool is under development."


@app.route('/subdomain')
def subdomain():
    return "Subdomain Finder Tool is under development."


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
            s.settimeout(0.5)
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
