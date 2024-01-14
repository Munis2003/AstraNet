from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
from pymongo import MongoClient
import socket
import whois
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests
import subprocess
import tldextract
import requests

#----------------------------------------- [Constants] ---------------------------------------------#

IMPORTANT_PORTS = [21, 22, 25, 53, 80, 443]
NEWS_API_KEY = 'd1b74e415a1b42c2b72d1ffb95df081c'
# Initialize CensysSubdomainFinder
# censys_subdomain_finder = CensysSubdomainFinder(api_id='11e5cd65-e420-4a6f-aa37-9558e78517f1', api_secret='8UoYDMOVlWZeqJRDbNoTJbx5VhIPorw9')

#----------------------------------------- [Flask Setup] ---------------------------------------------#

app = Flask(__name__)
CORS(app)

#----------------------------------------- [Mongo Setup] ---------------------------------------------#

client = MongoClient("mongodb://localhost:27017/")
db = client["astranet_db"]


#----------------------------------------- [Routes] ---------------------------------------------#

#------ Home ------
@app.route('/')
def home():
    return render_template('index.html')

#----------------------------------- WHOIS Lookup -------------------------------------------

@app.route('/whois-lookup', methods=['GET', 'POST'])
def whois_lookup():
    if request.method == 'POST':
        domain = request.form['domain']
        result = perform_whois_lookup(domain)

        # Store the WHOIS data in MongoDB
        if not result.get("error"):
            whois_collection = db["whois_results"]  # Create a new collection for WHOIS results
            whois_collection.insert_one({
                "domain": domain,
                "whois_info": result["whois_info"]
            })

        return jsonify(result)
    return render_template('whois_lookup.html')

#----------------------------------- DNS Lookup ---------------------------------------------

@app.route('/dns-lookup')
def dns_lookup():
    return render_template('dns_lookup.html')

@app.route('/execute-dns-lookup', methods=['POST'])
def execute_dns_lookup():
    domain = request.form['domain']
    results = perform_dns_lookup(domain)

    # Store DNS lookup results in MongoDB
    dns_collection = db["dns_results"]  # Create a new collection for DNS lookup results
    dns_collection.insert_one({
        "domain": domain,
        "dns_info": results
    })

    return jsonify(results)

#------------------------------------ Port Scan -----------------------------------------------

@app.route('/port-scan')
def port_scan():
    return render_template('port_scan.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    start_port = int(request.form.get('startPort', 1))
    end_port = int(request.form.get('endPort', 1024))
    open_ports_details = main(target, ports=range(start_port, end_port + 1))

    os_guess = guess_os(open_ports_details)

    # Store port scan results in MongoDB
    port_scan_collection = db["port_scan_results"]  # Create a new collection for port scan results
    port_scan_collection.insert_one({
        "domain": target,
        "os_guess": os_guess,
        "results": open_ports_details
    })

    return jsonify({
        "os_guess": os_guess,
        "open_ports_details": open_ports_details
    })


#-------------------------------------- Directory Enumeration ---------------------------------

@app.route('/directory-enumeration', methods=['GET', 'POST'])
def directory_enumeration():
    if request.method == 'POST':
        url = request.form['url']
        dir_enum_result = perform_directory_enumeration(url)

        # Store directory enumeration results in MongoDB
        dir_enum_collection = db["directory_enumeration_results"]  # Create a new collection for directory enumeration results
        dir_enum_collection.insert_one({
            "url": url,
            "directory_results": dir_enum_result.get("directory_results")
        })

        return jsonify(dir_enum_result)

    return render_template('directory_enumeration.html')



#----------------------------------- Subdomain Finder ---------------------------------------------

@app.route('/subdomain-finder', methods=['GET' , 'POST'])
def subdomain_finder():
    if request.method == 'POST':
        try:
            data = request.get_json()
            domain = data['domain']
            subdomains = find_subdomains(domain)

            # Store subdomain finder results in MongoDB
            subdomain_collection = db["subdomain_finder_results"]  # Create a new collection for subdomain finder results
            subdomain_collection.insert_one({
                "domain": domain,
                "subdomains": subdomains
            })

            return jsonify({"domain": domain, "subdomains": subdomains})
        except KeyError:
            return jsonify({"error": "Missing 'domain' in JSON payload"})
    return render_template('subdomain_finder.html')

def perform_dns_lookup(subdomain):
    try:
        # Perform DNS lookup
        result = socket.gethostbyname(subdomain)
        return True
    except socket.gaierror:
        # DNS lookup failed
        return False
    except Exception as e:
        # Other exceptions
        print(f"Error performing DNS lookup for {subdomain}: {e}")
        return False

def perform_dns_lookup(subdomain):
    try:
        # Perform DNS lookup
        result = socket.gethostbyname(subdomain)
        return True
    except socket.gaierror:
        # DNS lookup failed
        return False
    except Exception as e:
        # Log or handle DNS lookup errors more gracefully
        print(f"Error performing DNS lookup for {subdomain}: {e}")
        return False


@app.route('/api/cybersecurity-news', methods=['GET'])
def cybersecurity_news():
    try:
        # Define the News API endpoint for cybersecurity news
        news_api_url = 'https://newsapi.org/v2/everything'
        params = {
            'q': 'cybersecurity',
            'apiKey': NEWS_API_KEY
        }

        # Make the request to the News API
        response = requests.get(news_api_url, params=params)
        news_data = response.json()

        # Extract relevant information from the response
        articles = news_data.get('articles', [])

        # Return the news articles as JSON
        return jsonify({'news': articles})

    except Exception as e:
        return jsonify({"error": str(e)})


#----------------------------------------- [Helper Functions] ---------------------------------------------#

#----------------------------------------- DNS Lookup --------------------------------

def perform_dns_lookup(domain):
    try:
        # Perform DNS lookup and process the data
        a_records = None
        aaaa_records = None
        cname_records = None
        txt_records = None
        ns_records = None
        mx_records = None
        soa_record = None

        # A Records
        ip_addresses = [str(info[4][0]) for info in socket.getaddrinfo(domain, None)]
        if ip_addresses:
            a_records = {"ipv4": ip_addresses[0]}

        # AAAA Records (IPv6)
        aaaa_records = get_aaaa_records(domain)

        # CNAME Records
        cname_records = get_cname_records(domain)

        # TXT Records
        txt_records = get_txt_records(domain)

        # NS Records
        ns_records = get_ns_records(domain)

        # MX Records
        mx_records = get_mx_records(domain)

        # SOA Record
        soa_record = get_soa_record(domain)

        return {
            "domain": domain,
            "a_records": a_records,
            "cname_records": cname_records,
            "aaaa_records": aaaa_records,
            "txt_records": txt_records,
            "ns_records": ns_records,
            "mx_records": mx_records,
            "soa_record": soa_record
        }
    except Exception as e:
        return {"error": str(e)}


def get_cname_records(domain):
    try:
        cname_records = [str(answer.target) for answer in dns.resolver.resolve(domain, 'CNAME')]
        return cname_records
    except dns.resolver.NoAnswer:
        return None
    except Exception as e:
        return str(e)
    
def get_aaaa_records(domain):
    try:
        aaaa_records = [str(answer) for answer in dns.resolver.resolve(domain, 'AAAA')]
        return aaaa_records
    except dns.resolver.NoAnswer:
        return None
    except Exception as e:
        return str(e)

def get_txt_records(domain):
    try:
        txt_records = [str(answer) for answer in dns.resolver.resolve(domain, 'TXT')]
        return txt_records
    except dns.resolver.NoAnswer:
        return None
    except Exception as e:
        return str(e)

def get_ns_records(domain):
    try:
        ns_records = [str(answer) for answer in dns.resolver.resolve(domain, 'NS')]
        return ns_records
    except dns.resolver.NoAnswer:
        return None
    except Exception as e:
        return str(e)

def get_mx_records(domain):
    try:
        mx_records = [{"mail_server": str(answer.exchange), "priority": answer.preference}
                      for answer in dns.resolver.resolve(domain, 'MX')]
        return mx_records
    except dns.resolver.NoAnswer:
        return None
    except Exception as e:
        return str(e)

def get_soa_record(domain):
    try:
        soa_record = dns.resolver.resolve(domain, 'SOA')
        return {
            "start_of_authority": str(soa_record[0].mname),
            "email": str(soa_record[0].rname),
            "serial": soa_record[0].serial,
            "refresh": soa_record[0].refresh,
            "retry": soa_record[0].retry,
            "expire": soa_record[0].expire,
            "negative_cache_ttl": soa_record[0].minimum
        }
    except dns.resolver.NoAnswer:
        return None
    except Exception as e:
        return str(e)
    

#--------------------------------- WHOIS Lookup --------------------------------------------

def perform_whois_lookup(domain):
    try:
        whois_info = whois.whois(domain)
        # Process the WHOIS information as needed
        # You can return the raw WHOIS data or specific details from it
        print(whois_info)
        return {"domain": domain, "whois_info": whois_info}
    except Exception as e:
        return {"error": str(e)}


#--------------------------------- Port Scan --------------------------------------------

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

# ----------------------------------------- Direcotry Enumeration --------------------------------------------

def perform_directory_enumeration(url):
    try:
        # List of common directory names to check
        # List of common directory names to check
        common_directories = [

            'programmes','admin', 'images', 'uploads', 'backup', 'test', 'temp', 'css', 'js',
            'fonts', 'config', 'includes', 'data', 'lib', 'media', 'web', 'public',
            'private', 'bin', 'cgi-bin', 'html', 'docs', 'tmp', 'log', 'system',
            'files', 'backup', 'dist', 'src', 'assets', 'themes', 'uploads',
            'webroot', 'temp', 'scripts', 'config', 'conf', 'backup', 'cron',
            'tools', 'utilities', 'install', 'shell', 'sql', 'database', 'lib',
            'webdav', 'cronjobs', 'info', 'debug', 'tmp', 'secure', 'data',
            'includes', 'application', 'upload', 'user', 'users', 'adminpanel',
            'common', 'webadmin', 'panel', 'control', 'adm', 'manage', 'system',
            'install', 'installations', 'installing', 'installer', 'installers',
            'setup', 'configurator', 'configuration', 'console', 'core', 'api',
            'cgi', 'webcgi', 'api-docs', 'apidoc', 'rpc', 'doc', 'docs', 'swagger',
            'api-docs', 'apidoc', 'swagger-docs', 'swaggerdoc'
            
        ]
        
        results = {}
        for directory in common_directories:
            full_url = urljoin(url, directory)
            response = requests.head(full_url)  # Use requests.head for faster header check

            if response.status_code == 200:
                results[directory] = "Exists"
            elif response.status_code == 404:
                results[directory] = "Not Found"
            else:
                results[directory] = f"Status Code: {response.status_code}"

        return {"url": url, "directory_results": results}

    except Exception as e:
        return {"error": str(e)}


#----------------------------------- Subdomain Finder ---------------------------------------------

def find_subdomains(domain):
    try:
        subdomains = []

        # Extract the domain and top-level domain using tldextract
        ext = tldextract.extract(domain)
        base_domain = ext.domain + "." + ext.suffix

        # Common subdomains to check
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'blog', 'webmail']

        # Check common subdomains using DNS resolution
        for subdomain in common_subdomains:
            subdomain_url = f"{subdomain}.{base_domain}"
            is_working = perform_dns_lookup(subdomain_url)
            subdomains.append({"subdomain": subdomain_url, "is_working": is_working})

        return subdomains
    except Exception as e:
        return {"error": str(e)}




if __name__ == '__main__':
    app.run(debug=True)