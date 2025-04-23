import os
import datetime
import http.client
import re
import socket
import ssl
import urllib.parse
import whois
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import tempfile
import subprocess
import xml.etree.ElementTree as ET
import OpenSSL
from bs4 import BeautifulSoup
import random

class EnhancedDomainScanner:
    def __init__(self, domain):
        # Clean and validate domain
        domain = re.sub(r'https?://|:[0-9]+', '', domain.lower()).split('/')[0]
        if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', domain):
            raise ValueError("Invalid domain format")
            
        self.domain = domain
        self.wordlist_path = os.path.join('wordlists', 'directory_wordlist.txt')
        self.timeout = 5
        self.max_threads = 50  # Increased threads for faster scanning
        self.scan_active = True
        self.current_status = "Initializing"
        self.progress = 0
        
        # Results storage
        self.whois_results = {}
        self.dns_results = []
        self.geo_results = {}
        self.port_results = []
        self.subdomain_results = []
        self.ssl_results = {}
        self.found_urls = []
        self.directory_stats = {'total': 0, 'processed': 0}
        self.log_messages = []
        self.vuln_results = []
        self.os_detection = {}
        
        # Create wordlist directory if not exists
        os.makedirs('wordlists', exist_ok=True)
        
        # Generate wordlist if not exists
        if not os.path.exists(self.wordlist_path):
            self._create_extensive_wordlist()

    def update_status(self, message, progress=None):
        self.current_status = message
        if progress is not None:
            self.progress = progress
        self._log(f"[STATUS] {message}")

    def _log(self, message, level="info"):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            'timestamp': timestamp,
            'message': message,
            'level': level
        }
        self.log_messages.append(log_entry)

    def _create_extensive_wordlist(self):
        """Create an extensive wordlist with 5000+ entries for directory scanning"""
        # Common directories and files
        common_entries = [
            # Admin interfaces
            'admin', 'administrator', 'adminpanel', 'adminarea', 'admin-login', 
            'admin_login', 'admin1', 'admin2', 'admin4', 'admin5',
            
            # Common directories
            'backup', 'backups', 'bak', 'old', 'temp', 'tmp', 'log', 'logs',
            'config', 'configuration', 'db', 'database', 'data', 'download',
            'downloads', 'upload', 'uploads', 'file', 'files', 'doc', 'docs',
            
            # Framework specific
            'wp-admin', 'wp-content', 'wp-includes', 'wordpress', 'joomla',
            'drupal', 'magento', 'laravel', 'symfony', 'yii', 'codeigniter',
            
            # API endpoints
            'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'restapi', 'graphql',
            'swagger', 'swagger-ui', 'openapi', 'redoc',
            
            # Configuration files
            '.env', '.env.production', '.env.development', 'config.php',
            'configuration.php', 'settings.php', 'web.config', '.htaccess',
            '.htpasswd', 'robots.txt', 'security.txt',
            
            # Backup files
            'backup.zip', 'backup.tar', 'backup.tar.gz', 'backup.sql',
            'database.sql', 'dump.sql', 'backup.rar', 'backup.7z',
            
            # Documentation
            'readme.md', 'readme.txt', 'license.txt', 'changelog.txt',
            'release-notes.txt', 'documentation', 'docs',
            
            # Developer tools
            'phpinfo.php', 'info.php', 'test.php', 'debug.php', 'console',
            'shell', 'sh', 'bash', 'cmd', 'command', 'terminal',
            
            # Common files
            'index.php', 'index.html', 'index.jsp', 'index.asp', 'index.aspx',
            'main.php', 'home.php', 'login.php', 'register.php', 'signup.php',
            'account.php', 'profile.php', 'user.php', 'users.php',
            
            # Database files
            'db.sql', 'db.sqlite', 'database.db', 'data.db', 'users.db',
            'products.db', 'customers.db', 'orders.db',
            
            # Git files
            '.git/config', '.git/HEAD', '.git/index', '.git/logs/HEAD',
            '.git/logs/refs/heads/master', '.git/logs/refs/remotes/origin/HEAD',
            
            # SVN files
            '.svn/entries', '.svn/wc.db', '.svn/format', '.svn/all-wcprops',
            
            # IDE files
            '.idea/workspace.xml', '.idea/modules.xml', '.project',
            '.classpath', '.settings/org.eclipse.core.resources.prefs',
            
            # More common files
            'composer.json', 'package.json', 'bower.json', 'yarn.lock',
            'Gemfile', 'Gemfile.lock', 'requirements.txt', 'Pipfile',
            'Pipfile.lock', 'go.mod', 'go.sum'
        ]
        
        # Generate variations with extensions
        extensions = ['', '.php', '.html', '.htm', '.jsp', '.asp', '.aspx',
                     '.bak', '.old', '.orig', '.save', '.swp', '.tmp', '.temp',
                     '.txt', '.json', '.xml', '.yml', '.yaml', '.ini', '.conf',
                     '.sql', '.db', '.tar.gz', '.zip', '.rar', '.7z', '.gz']
        
        # Add numbers from 0 to 100
        number_entries = [str(i) for i in range(101)]
        
        # Combine all entries
        all_entries = common_entries + number_entries
        
        # Generate all possible combinations
        wordlist = set()
        for entry in all_entries:
            for ext in extensions:
                if ext:
                    wordlist.add(f"{entry}{ext}")
                    wordlist.add(f"{entry}.{ext}")  # For backup files
                else:
                    wordlist.add(entry)
        
        # Add some random strings
        random_strings = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(3, 10))) 
                         for _ in range(500)]
        wordlist.update(random_strings)
        
        # Write to file
        with open(self.wordlist_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(wordlist))

    def check_port(self, port):
        """Check if a port is open on the target domain."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.domain, port))
            sock.close()
            return result == 0
        except Exception as e:
            self._log(f"Error checking port {port}: {str(e)}", "error")
            return False

    def _check_url(self, path):
        """Check if a URL exists and return its status code."""
        url = f"https://{self.domain}{path}"
        try:
            response = requests.head(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            self.directory_stats['processed'] += 1
            return url, response.status_code, response.headers.get('content-length', '0')
        except requests.RequestException:
            try:
                url = f"http://{self.domain}{path}"
                response = requests.head(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                self.directory_stats['processed'] += 1
                return url, response.status_code, response.headers.get('content-length', '0')
            except requests.RequestException as e:
                self._log(f"URL check failed for {path}: {str(e)}", "debug")
                self.directory_stats['processed'] += 1
                return url, 0, '0'

    def get_whois_info(self):
        self.update_status("Gathering WHOIS information", 10)
        try:
            w = whois.whois(self.domain)
            self.whois_results = {
                'Domain Name': w.domain_name,
                'Registrar': w.registrar,
                'Creation Date': w.creation_date,
                'Expiration Date': w.expiration_date,
                'Updated Date': w.updated_date,
                'Name Servers': ', '.join(w.name_servers) if w.name_servers else 'N/A',
                'Organization': w.org,
                'Address': w.address,
                'City': w.city,
                'State': w.state,
                'Country': w.country
            }
            self._log("WHOIS information retrieved successfully", "success")
        except Exception as e:
            self.whois_results = {'Error': 'WHOIS lookup failed: ' + str(e)}
            self._log(f"WHOIS lookup failed: {str(e)}", "error")
            # Continue with the scan even if WHOIS fails
                
    def get_dns_records(self):
        self.update_status("Gathering DNS records", 20)
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type, lifetime=5)
                for rdata in answers:
                    self.dns_results.append(f"{record_type} Record: {rdata.to_text()}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception as e:
                self._log(f"Error retrieving {record_type} record: {str(e)}", "error")
                continue
        
        if not self.dns_results:
            self.dns_results.append("No DNS records found or DNS lookup failed")

    def dns_enumeration(self):
        """Advanced subdomain enumeration with multiple techniques"""
        self.update_status("Enumerating subdomains", 50)
        found_subdomains = set()
        
        # Technique 1: Common subdomain brute force
        common_subdomains = self._load_subdomain_wordlist()
        found_subdomains.update(self._brute_force_subdomains(common_subdomains))
        
        # Technique 2: Certificate Transparency logs
        found_subdomains.update(self._search_certificate_transparency())
        
        # Technique 3: Search engines (Google, Bing)
        found_subdomains.update(self._search_engines_subdomains())
        
        self.subdomain_results = sorted(list(found_subdomains))
        self._log(f"Found {len(self.subdomain_results)} subdomains", "success")

    def _brute_force_subdomains(self, subdomains):
        """Brute force subdomains with DNS resolution"""
        found = set()
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._resolve_subdomain, f"{sub}.{self.domain}"): sub
                for sub in subdomains
            }
            
            for future in as_completed(futures):
                if not self.scan_active:
                    break
                sub = futures[future]
                try:
                    result = future.result()
                    if result:
                        found.add(result)
                except Exception:
                    continue
        return found

    def _resolve_subdomain(self, subdomain):
        """Resolve a subdomain to check if it exists"""
        try:
            # First try A record
            answers = dns.resolver.resolve(subdomain, 'A', lifetime=3)
            if answers:
                return subdomain
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass
        
        try:
            # Then try CNAME record
            answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=3)
            if answers:
                return subdomain
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass
        
        return None

    def get_geolocation(self):
        self.update_status("Gathering IP geolocation", 30)
        try:
            ip = socket.gethostbyname(self.domain)
            url = f"https://ipinfo.io/{ip}/json"
            response = requests.get(url, timeout=self.timeout)
            data = response.json()
            
            self.geo_results = {
                'IP Address': data.get('ip', 'N/A'),
                'Hostname': data.get('hostname', 'N/A'),
                'Country': f"{data.get('country', 'N/A')} ({data.get('country_name', 'N/A')})",
                'Region': data.get('region', 'N/A'),
                'City': data.get('city', 'N/A'),
                'Location': data.get('loc', 'N/A'),
                'Organization': data.get('org', 'N/A'),
                'Postal': data.get('postal', 'N/A'),
                'Timezone': data.get('timezone', 'N/A')
            }
            self._log("Geolocation data retrieved successfully", "success")
        except Exception as e:
            self.geo_results = {'Error': 'Geolocation lookup failed'}
            self._log(f"Geolocation lookup failed: {str(e)}", "error")

    def _run_nmap_scan(self, ip):
        """Enhanced Nmap scan with better OS detection and vulnerability scanning"""
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                xml_output = tmp_file.name

            nmap_cmd = [
                'nmap', '-T4', '-A', '-v', '-O', '--osscan-guess',
                '--version-intensity', '7', '--script', 'vulners,vuln',
                '-oX', xml_output, ip
            ]
            
            self._log(f"Running Nmap command: {' '.join(nmap_cmd)}", "debug")
            subprocess.run(nmap_cmd, timeout=600, check=True)
            
            self._parse_nmap_results(xml_output)
            
            os.unlink(xml_output)
            
        except subprocess.TimeoutExpired:
            self._log("Nmap scan timed out - partial results may be available", "warning")
        except Exception as e:
            self._log(f"Nmap scan failed: {str(e)}", "error")

    def _parse_nmap_results(self, xml_file):
        """Improved Nmap XML parsing with better OS detection"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            os_matches = []
            for osmatch in root.findall('.//osmatch'):
                os_matches.append({
                    'name': osmatch.get('name'),
                    'accuracy': osmatch.get('accuracy'),
                    'line': osmatch.get('line')
                })
            
            if os_matches:
                best_match = max(os_matches, key=lambda x: float(x['accuracy']))
                self.os_detection = {
                    'os_name': best_match['name'],
                    'accuracy': f"{best_match['accuracy']}%",
                    'details': best_match['line']
                }
                self._log(f"OS Detection: {self.os_detection['os_name']} ({self.os_detection['accuracy']})", "success")
            
            for script in root.findall('.//script'):
                if 'vuln' in script.get('id') or 'vulners' in script.get('id'):
                    output = script.get('output')
                    if output and 'No vulnerabilities found' not in output:
                        self.vuln_results.append({
                            'id': script.get('id'),
                            'output': output
                        })
                        self._log(f"Vulnerability found: {script.get('id')}", "warning")
            
            for port in root.findall('.//port'):
                if port.find('state').get('state') == 'open':
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    service = port.find('service')
                    
                    service_info = {
                        'port': port_id,
                        'protocol': protocol,
                        'name': service.get('name'),
                        'product': service.get('product'),
                        'version': service.get('version'),
                        'extrainfo': service.get('extrainfo')
                    }
                    
                    if not any(p['port'] == port_id for p in self.port_results):
                        self.port_results.append(service_info)
                        self._log(f"Open port: {port_id}/{protocol} ({service.get('name')})", "info")
                    
        except Exception as e:
            self._log(f"Error parsing Nmap results: {str(e)}", "error")

    def _load_subdomain_wordlist(self):
        """Load an extensive subdomain wordlist"""
        wordlist = [
            'www', 'mail', 'webmail', 'admin', 'blog', 'dev', 'test',
            'staging', 'api', 'secure', 'vpn', 'm', 'mobile', 'old',
            'new', 'beta', 'alpha', 'chat', 'support', 'help', 'cpanel',
            'whm', 'webdisk', 'webmin', 'autodiscover', 'imap', 'pop',
            'smtp', 'git', 'svn', 'ftp', 'download', 'cdn', 'media',
            'static', 'assets', 'images', 'img', 'js', 'css', 'app',
            'apps', 'portal', 'intranet', 'internal', 'external', 'demo',
            'test', 'testing', 'stage', 'staging', 'prod', 'production',
            'live', 'status', 'monitor', 'monitoring', 'stats', 'analytics',
            'metrics', 'db', 'database', 'sql', 'mysql', 'mssql', 'oracle',
            'postgres', 'redis', 'memcached', 'mongodb', 'elasticsearch',
            'solr', 'kibana', 'grafana', 'prometheus', 'jenkins', 'ci',
            'gitlab', 'github', 'bitbucket', 'jira', 'confluence', 'wiki',
            'docs', 'documentation', 'helpdesk', 'tickets', 'support',
            'kb', 'knowledgebase', 'forum', 'forums', 'community', 'shop',
            'store', 'cart', 'checkout', 'billing', 'payment', 'payments',
            'account', 'accounts', 'login', 'signin', 'register', 'signup',
            'auth', 'authentication', 'oauth', 'sso', 'admin', 'administrator',
            'backend', 'backoffice', 'cp', 'controlpanel', 'dashboard',
            'manager', 'management', 'sysadmin', 'system', 'root', 'superuser'
        ]
        
        wordlist_path = os.path.join('wordlists', 'subdomains.txt')
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                wordlist.extend([line.strip() for line in f if line.strip()])
        return wordlist

    def _search_engines_subdomains(self):
        """Find subdomains using search engines"""
        subdomains = set()
        try:
            url = f"https://www.google.com/search?q=site:{self.domain}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and self.domain in href:
                    subdomain = re.search(r'(https?://)?([a-z0-9.-]+)\.' + re.escape(self.domain), href)
                    if subdomain:
                        subdomains.add(subdomain.group(2))
            
        except Exception as e:
            self._log(f"Search engine subdomain search failed: {str(e)}", "error")
        return subdomains

    def check_ssl_certificate(self):
        """Comprehensive SSL/TLS certificate analysis"""
        self.update_status("Analyzing SSL/TLS configuration", 70)
        
        if not self.check_port(443):
            self.ssl_results = {'Status': 'Port 443 closed'}
            return
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    
                    subject = dict(x[0] for x in ssock.getpeercert().get('subject', []))
                    issuer = dict(x[0] for x in ssock.getpeercert().get('issuer', []))
                    
                    not_before = x509.get_notBefore().decode('ascii')
                    not_after = x509.get_notAfter().decode('ascii')
                    
                    not_before_date = datetime.datetime.strptime(not_before, '%Y%m%d%H%M%SZ').strftime('%d %B %Y')
                    not_after_date = datetime.datetime.strptime(not_after, '%Y%m%d%H%M%SZ').strftime('%d %B %Y')
                    
                    vulns = self._check_ssl_vulnerabilities(ssock)
                    
                    self.ssl_results = {
                        'Subject': subject.get('commonName', 'N/A'),
                        'Issuer': issuer.get('organizationName', 'N/A'),
                        'Valid From': not_before_date,
                        'Valid Until': not_after_date,
                        'Signature Algorithm': x509.get_signature_algorithm().decode(),
                        'Version': x509.get_version() + 1,
                        'Serial Number': hex(x509.get_serial_number()),
                        'Public Key Bits': x509.get_pubkey().bits(),
                        'TLS Version': ssock.version(),
                        'Cipher': ssock.cipher()[0],
                        'Vulnerabilities': vulns
                    }
                    
                    self._log("SSL certificate analysis completed", "success")
        except Exception as e:
            self.ssl_results = {'Error': f'SSL analysis failed: {str(e)}'}
            self._log(f"SSL analysis failed: {str(e)}", "error")

    def _check_ssl_vulnerabilities(self, ssock):
        """Check for known SSL/TLS vulnerabilities"""
        vulns = []
        
        if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
            vulns.append(f"Weak protocol: {ssock.version()}")
        
        cipher = ssock.cipher()
        if cipher and ('RC4' in cipher[0] or 'DES' in cipher[0] or '3DES' in cipher[0]):
            vulns.append(f"Weak cipher: {cipher[0]}")
        
        try:
            if self._test_heartbleed(self.domain):
                vulns.append("Vulnerable to Heartbleed (CVE-2014-0160)")
        except:
            pass
            
        return vulns if vulns else ["No major vulnerabilities found"]

    def _load_directory_wordlist(self):
        """Load directory wordlist from file"""
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self._log(f"Error loading directory wordlist: {str(e)}", "error")
            return []

    def directory_traversal_scan(self):
        """Advanced directory and file scanning with 5000+ entries"""
        self.update_status("Scanning directories and files", 80)
        
        dir_wordlist = self._load_directory_wordlist()
        self.directory_stats['total'] = len(dir_wordlist)
        self.directory_stats['processed'] = 0
        self.found_urls = []
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_url = {
                    executor.submit(self._check_url, f"/{path}"): path 
                    for path in dir_wordlist
                }
                
                for future in as_completed(future_to_url):
                    if not self.scan_active:
                        break
                    
                    path = future_to_url[future]
                    progress = 80 + int(20 * (self.directory_stats['processed'] / self.directory_stats['total']))
                    self.update_status(f"Scanning {self.directory_stats['processed']}/{self.directory_stats['total']} paths", progress)
                    
                    try:
                        url, status, size = future.result()
                        if status in [200, 403, 401, 500, 301, 302]:
                            self.found_urls.append({
                                'url': url,
                                'status': status,
                                'size': size
                            })
                            self._log(f"Found path: [{status}] {url} (Size: {size})", "info")
                    except Exception as e:
                        self._log(f"Error checking URL {path}: {str(e)}", "debug")
                        continue
            
            self._log(f"Directory scan completed. Found {len(self.found_urls)} interesting paths", "success")
        except Exception as e:
            self._log(f"Directory scan failed: {str(e)}", "error")

    def port_scan(self):
        self.update_status("Scanning ports and detecting services", 40)
        self.port_results = []
        self.vuln_results = []
        self.os_detection = {}
        
        common_ports = {
            20: 'FTP (Data)', 21: 'FTP (Control)', 22: 'SSH', 
            23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 
            110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS',
            587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 2049: 'NFS', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 
            8080: 'HTTP Alt', 8443: 'HTTPS Alt', 8888: 'Alternative HTTP',
            9200: 'Elasticsearch', 10000: 'Webmin'
        }
        
        try:
            ip = socket.gethostbyname(self.domain)
            self._log(f"Starting port scan for IP: {ip}", "info")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_port = {executor.submit(self.check_port, port): port for port in common_ports}
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    if not self.scan_active:
                        break
                        
                    if future.result():
                        service = common_ports.get(port, 'Unknown')
                        self.port_results.append({
                            'port': port,
                            'service': service,
                            'status': 'Open'
                        })
                        self._log(f"Found open port: {port} ({service})", "info")
            
            self._run_nmap_scan(ip)
            
        except Exception as e:
            self._log(f"Error in port scan: {str(e)}", "error")

    def _search_certificate_transparency(self):
        """Search Certificate Transparency logs for subdomains."""
        found_domains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for item in data:
                    domain = item.get('name_value', '').lower()
                    if domain.startswith('*.') or domain == self.domain:
                        continue
                    if domain.endswith(f".{self.domain}"):
                        found_domains.add(domain)
        except Exception as e:
            self._log(f"Certificate Transparency search error: {str(e)}", "error")
        
        return found_domains

    def scan(self):
        """Main scan method that runs all scan components."""
        self._log(f"=== Starting scan for {self.domain} ===", "info")
        self._log(f"Scan started at: {datetime.datetime.now()}", "info")
        
        scan_methods = [
            self.get_whois_info,
            self.get_dns_records,
            self.get_geolocation,
            self.port_scan,
            self.dns_enumeration,
            self.check_ssl_certificate,
            self.directory_traversal_scan
        ]
        
        for method in scan_methods:
            if not self.scan_active:
                self._log("Scan stopped by user", "warning")
                break
            try:
                method()
            except Exception as e:
                self._log(f"Error in {method.__name__}: {str(e)}", "error")
                continue
        
        if self.scan_active:
            self._log(f"=== Scan completed at {datetime.datetime.now()} ===", "success")
            self.update_status("Scan completed", 100)
            self.scan_active = False  # ✅ This ensures the frontend sees the correct status

        else:
            self._log("Scan was stopped before completion", "warning")

    def stop_scan(self):
        """Stop the ongoing scan."""
        self.update_status("Scan completed", 100)
        self.scan_active = False  # <-- this is what you're missing
        self._log("Scan stopped by user", "warning")
        self.update_status("Scan stopped", self.progress)