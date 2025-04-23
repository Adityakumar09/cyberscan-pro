import os
import datetime
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import threading
from io import BytesIO
import re
from scanner import EnhancedDomainScanner

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

active_scans = {}

def validate_domain(domain):
    """Validate domain format"""
    pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    return re.match(pattern, domain, re.IGNORECASE) is not None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    if not validate_domain(domain):
        return jsonify({'error': 'Invalid domain format'}), 400
    
    # Stop any existing scan for this domain
    if domain in active_scans:
        active_scans[domain].stop_scan()
        del active_scans[domain]
    
    # Create and start scanner
    try:
        scanner = EnhancedDomainScanner(domain)
        active_scans[domain] = scanner
        
        thread = threading.Thread(target=scanner.scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'message': f'Scan started for {domain}',
            'domain': domain
        })
    except Exception as e:
        return jsonify({'error': f'Failed to start scan: {str(e)}'}), 500

@app.route('/scan_status/<domain>')
def scan_status(domain):
    if domain not in active_scans:
        return jsonify({
            'error': 'No active scan for this domain',
            'active': False
        }), 404
    
    scanner = active_scans[domain]
    
    try:
        return jsonify({
            'status': scanner.current_status,
            'progress': scanner.progress,
            'scan_results': {
                'whois': scanner.whois_results,
                'dns': scanner.dns_results,
                'geolocation': scanner.geo_results,
                'ports': scanner.port_results,
                'subdomains': scanner.subdomain_results,
                'ssl': scanner.ssl_results,
                'os_detection': getattr(scanner, 'os_detection', {}),
                'vulnerabilities': getattr(scanner, 'vuln_results', []),
                'directory_scan': {
                    'found_urls': getattr(scanner, 'found_urls', []),
                    'stats': getattr(scanner, 'directory_stats', {'total': 0})
                }
            },
            'active': scanner.scan_active,
            'log_messages': scanner.log_messages[-50:]  # Return last 50 log messages
        })
    except Exception as e:
        return jsonify({
            'error': f'Error getting scan status: {str(e)}',
            'active': False
        }), 500

@app.route('/stop_scan/<domain>')
def stop_scan(domain):
    if domain not in active_scans:
        return jsonify({'error': 'No active scan for this domain'}), 404
    
    try:
        active_scans[domain].stop_scan()
        return jsonify({'message': f'Scan stopped for {domain}'})
    except Exception as e:
        return jsonify({'error': f'Error stopping scan: {str(e)}'}), 500

@app.route('/download_results/<domain>')
def download_results(domain):
    if domain not in active_scans:
        return jsonify({'error': 'No results available for this domain'}), 404
    
    scanner = active_scans[domain]
    
    try:
        report = generate_report(scanner)
        
        str_io = BytesIO()
        str_io.write(report.encode('utf-8'))
        str_io.seek(0)
        
        return send_file(
            str_io,
            mimetype='text/plain',
            as_attachment=True,
            download_name=f'pentest_report_{domain}.txt'
        )
    except Exception as e:
        return jsonify({'error': f'Error generating report: {str(e)}'}), 500

def generate_report(scanner):
    """Generate a comprehensive text report of scan results"""
    report = f"=== CyberScan Pro Report for {scanner.domain} ===\n"
    report += f"Generated at: {datetime.datetime.now()}\n\n"
    
    # WHOIS Information
    report += "=== WHOIS Information ===\n"
    for key, value in (scanner.whois_results or {}).items():
        report += f"{key}: {value}\n"
    
    # DNS Records
    report += "\n=== DNS Records ===\n"
    for record in (scanner.dns_results or []):
        report += f"{record}\n"
    
    # Geolocation
    report += "\n=== Geolocation ===\n"
    for key, value in (scanner.geo_results or {}).items():
        report += f"{key}: {value}\n"
    
    # Open Ports
    report += "\n=== Open Ports ===\n"
    for port in (scanner.port_results or []):
        report += f"{port}\n"
    
    # Subdomains
    report += "\n=== Subdomains ===\n"
    if scanner.subdomain_results:
        for sub in scanner.subdomain_results:
            report += f"{sub}\n"
    else:
        report += "No subdomains found\n"
    
    # SSL Certificate
    report += "\n=== SSL Certificate ===\n"
    for key, value in (scanner.ssl_results or {}).items():
        report += f"{key}: {value}\n"
    
    # Directory Scan Results
    report += "\n=== Directory Scan Results ===\n"
    stats = getattr(scanner, 'directory_stats', {'total': 0})
    found_urls = getattr(scanner, 'found_urls', [])
    
    report += f"Total URLs checked: {stats.get('total', 0)}\n"
    report += f"200 OK: {len([u for u in found_urls if u.get('status') == 200])}\n"
    report += f"403 Forbidden: {len([u for u in found_urls if u.get('status') == 403])}\n"
    report += f"Other responses: {len([u for u in found_urls if u.get('status') not in [200, 403]])}\n"
    
    # Interesting URLs
    report += "\n=== Interesting URLs ===\n"
    for url in found_urls:
        status = url.get('status', 0)
        if status in [200, 403, 401, 500]:
            report += f"[{status}] {url.get('url', '')}\n"
    
    # Vulnerabilities
    if getattr(scanner, 'vuln_results', []):
        report += "\n=== Potential Vulnerabilities ===\n"
        for vuln in scanner.vuln_results:
            report += f"- {vuln}\n"
    
    # OS Detection
    if getattr(scanner, 'os_detection', {}):
        report += "\n=== OS Detection ===\n"
        os_info = scanner.os_detection
        report += f"Detected OS: {os_info.get('os_name', 'Unknown')}\n"
        report += f"Confidence: {os_info.get('accuracy', 'Unknown')}\n"
    
    return report

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)