from crewai.tools import BaseTool
from typing import Type, Any, Dict, List
from pydantic import BaseModel, Field
import subprocess
import requests
import socket
import time
import json
from urllib.parse import urlparse, urljoin
import logging

logger = logging.getLogger(__name__)

class HTTPRequestInput(BaseModel):
    """Input schema for HTTP request tool"""
    url: str = Field(..., description="URL to send request to")
    method: str = Field(default="GET", description="HTTP method (GET, POST, PUT, DELETE, etc.)")
    headers: Dict[str, str] = Field(default={}, description="HTTP headers")
    data: Dict[str, Any] = Field(default={}, description="Request data/payload")
    timeout: int = Field(default=30, description="Request timeout in seconds")

class NetworkScanInput(BaseModel):
    """Input schema for network scan tool"""
    target: str = Field(..., description="Target host or URL")
    ports: List[int] = Field(default=[], description="Specific ports to scan")
    timeout: int = Field(default=5, description="Connection timeout in seconds")

class CommandExecutionInput(BaseModel):
    """Input schema for command execution tool"""
    command: str = Field(..., description="Command to execute")
    timeout: int = Field(default=30, description="Command timeout in seconds")

class NetworkTool(BaseTool):
    """Tool for network operations and HTTP requests"""
    
    name: str = "Network Tool"
    description: str = (
        "Performs network operations including HTTP requests, port scanning, and basic network commands. "
        "Useful for dynamic vulnerability testing, reconnaissance, and exploitation attempts."
    )
    args_schema: Type[BaseModel] = HTTPRequestInput
    
    def _run(self, url: str, method: str = "GET", headers: Dict[str, str] = None, 
             data: Dict[str, Any] = None, timeout: int = 30) -> str:
        """Execute HTTP request"""
        try:
            return self.http_request(url, method, headers or {}, data or {}, timeout)
        except Exception as e:
            logger.error(f"Error executing HTTP request: {e}")
            return f"Error: {str(e)}"
    
    def http_request(self, url: str, method: str = "GET", headers: Dict[str, str] = None, 
                    data: Dict[str, Any] = None, timeout: int = 30) -> str:
        """Execute HTTP request with detailed response"""
        headers = headers or {}
        data = data or {}
        
        # Add default headers
        default_headers = {
            'User-Agent': 'GenIA-Security-Scanner/1.0',
            'Accept': '*/*',
            'Connection': 'close'
        }
        default_headers.update(headers)
        
        logger.info(f"Executing {method} request to {url}")
        
        try:
            session = requests.Session()
            session.headers.update(default_headers)
            
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = session.get(url, params=data, timeout=timeout)
            elif method.upper() == 'POST':
                response = session.post(url, data=data, timeout=timeout)
            elif method.upper() == 'PUT':
                response = session.put(url, data=data, timeout=timeout)
            elif method.upper() == 'DELETE':
                response = session.delete(url, timeout=timeout)
            elif method.upper() == 'HEAD':
                response = session.head(url, timeout=timeout)
            elif method.upper() == 'OPTIONS':
                response = session.options(url, timeout=timeout)
            else:
                response = session.request(method.upper(), url, data=data, timeout=timeout)
            
            response_time = time.time() - start_time
            
            # Prepare response summary
            result = {
                'url': url,
                'method': method.upper(),
                'status_code': response.status_code,
                'response_time': round(response_time, 3),
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'content_type': response.headers.get('Content-Type', 'Unknown')
            }
            
            # Add response body (truncated if too long)
            try:
                if response.headers.get('Content-Type', '').startswith('text/') or \
                   'json' in response.headers.get('Content-Type', ''):
                    content = response.text
                    if len(content) > 5000:  # Truncate long responses
                        result['content'] = content[:5000] + "\n... (truncated)"
                    else:
                        result['content'] = content
                else:
                    result['content'] = f"Binary content ({len(response.content)} bytes)"
            except:
                result['content'] = "Could not decode response content"
            
            # Add security-relevant headers
            security_headers = {
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'Set-Cookie': response.headers.get('Set-Cookie')
            }
            result['security_headers'] = {k: v for k, v in security_headers.items() if v}
            
            return json.dumps(result, indent=2)
            
        except requests.exceptions.Timeout:
            return f"Request timed out after {timeout} seconds"
        except requests.exceptions.ConnectionError:
            return f"Connection error: Could not connect to {url}"
        except requests.exceptions.RequestException as e:
            return f"Request error: {str(e)}"
        except Exception as e:
            return f"Unexpected error: {str(e)}"

class PortScanTool(BaseTool):
    """Tool for port scanning"""
    
    name: str = "Port Scanner"
    description: str = (
        "Scans network ports on target hosts. "
        "Useful for reconnaissance and identifying open services."
    )
    args_schema: Type[BaseModel] = NetworkScanInput
    
    def _run(self, target: str, ports: List[int] = None, timeout: int = 5) -> str:
        """Execute port scan"""
        try:
            return self.scan_ports(target, ports or [], timeout)
        except Exception as e:
            logger.error(f"Error scanning ports: {e}")
            return f"Error: {str(e)}"
    
    def scan_ports(self, target: str, ports: List[int] = None, timeout: int = 5) -> str:
        """Scan ports on target host"""
        # Extract hostname from URL if needed
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            hostname = parsed.hostname
            default_port = 443 if parsed.scheme == 'https' else 80
        else:
            hostname = target
            default_port = 80
        
        # Default ports to scan if none specified
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433, 6379]
        
        logger.info(f"Scanning {len(ports)} ports on {hostname}")
        
        open_ports = []
        closed_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((hostname, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    logger.debug(f"Port {port} is open")
                else:
                    closed_ports.append(port)
                    
            except socket.gaierror:
                return f"Error: Could not resolve hostname {hostname}"
            except Exception as e:
                logger.warning(f"Error scanning port {port}: {e}")
                closed_ports.append(port)
        
        result = {
            'target': hostname,
            'total_ports_scanned': len(ports),
            'open_ports': open_ports,
            'closed_ports_count': len(closed_ports),
            'scan_timeout': timeout
        }
        
        # Add service identification for open ports
        if open_ports:
            result['services'] = self._identify_services(hostname, open_ports)
        
        return json.dumps(result, indent=2)
    
    def _identify_services(self, hostname: str, ports: List[int]) -> Dict[int, str]:
        """Identify common services on open ports"""
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            1433: 'MSSQL',
            6379: 'Redis'
        }
        
        services = {}
        for port in ports:
            if port in common_services:
                services[port] = common_services[port]
            else:
                services[port] = 'Unknown'
        
        return services

class CommandExecutionTool(BaseTool):
    """Tool for executing safe network commands"""
    
    name: str = "Command Executor"
    description: str = (
        "Executes safe network commands like ping, curl, wget, netcat for testing purposes. "
        "Useful for network reconnaissance and basic exploitation testing."
    )
    args_schema: Type[BaseModel] = CommandExecutionInput
    
    def _run(self, command: str, timeout: int = 30) -> str:
        """Execute command"""
        try:
            return self.execute_command(command, timeout)
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return f"Error: {str(e)}"
    
    def execute_command(self, command: str, timeout: int = 30) -> str:
        """Execute safe network command"""
        # Whitelist of allowed commands for security
        allowed_commands = {
            'ping', 'curl', 'wget', 'nc', 'netcat', 'nslookup', 'dig', 'host',
            'telnet', 'ssh', 'ftp', 'whois', 'traceroute', 'mtr'
        }
        
        # Extract base command
        base_command = command.split()[0] if command.split() else ''
        
        if base_command not in allowed_commands:
            return f"Error: Command '{base_command}' is not allowed. Allowed commands: {', '.join(allowed_commands)}"
        
        logger.info(f"Executing command: {command}")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = {
                'command': command,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'execution_time': timeout  # Approximate
            }
            
            return json.dumps(output, indent=2)
            
        except subprocess.TimeoutExpired:
            return f"Command timed out after {timeout} seconds"
        except subprocess.SubprocessError as e:
            return f"Command execution error: {str(e)}"
        except Exception as e:
            return f"Unexpected error: {str(e)}"

class WebCrawlerTool(BaseTool):
    """Tool for basic web crawling and endpoint discovery"""
    
    name: str = "Web Crawler"
    description: str = (
        "Performs basic web crawling to discover endpoints and analyze web application structure. "
        "Useful for reconnaissance and finding potential attack vectors."
    )
    args_schema: Type[BaseModel] = HTTPRequestInput
    
    def _run(self, url: str, **kwargs) -> str:
        """Execute web crawling"""
        try:
            return self.crawl_website(url)
        except Exception as e:
            logger.error(f"Error crawling website: {e}")
            return f"Error: {str(e)}"
    
    def crawl_website(self, base_url: str, max_pages: int = 10) -> str:
        """Crawl website to discover endpoints"""
        logger.info(f"Crawling website: {base_url}")
        
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'GenIA-Security-Scanner/1.0'
            })
            
            discovered_urls = set()
            forms = []
            technologies = set()
            
            # Start with base URL
            to_visit = [base_url]
            visited = set()
            
            while to_visit and len(visited) < max_pages:
                current_url = to_visit.pop(0)
                if current_url in visited:
                    continue
                
                visited.add(current_url)
                
                try:
                    response = session.get(current_url, timeout=10)
                    if response.status_code == 200:
                        discovered_urls.add(current_url)
                        
                        # Extract links
                        import re
                        links = re.findall(r'href=["\']([^"\'>]+)["\']', response.text)
                        for link in links:
                            if link.startswith('/'):
                                full_url = urljoin(base_url, link)
                                if full_url not in visited and len(to_visit) < max_pages:
                                    to_visit.append(full_url)
                        
                        # Extract forms
                        form_matches = re.findall(r'<form[^>]*action=["\']([^"\'>]*)["\'][^>]*>', response.text, re.IGNORECASE)
                        for form_action in form_matches:
                            form_url = urljoin(current_url, form_action)
                            forms.append({
                                'url': form_url,
                                'found_on': current_url
                            })
                        
                        # Detect technologies
                        content = response.text.lower()
                        if 'jquery' in content:
                            technologies.add('jQuery')
                        if 'bootstrap' in content:
                            technologies.add('Bootstrap')
                        if 'angular' in content:
                            technologies.add('Angular')
                        if 'react' in content:
                            technologies.add('React')
                        if 'vue' in content:
                            technologies.add('Vue.js')
                        
                except Exception as e:
                    logger.warning(f"Error crawling {current_url}: {e}")
            
            result = {
                'base_url': base_url,
                'discovered_urls': list(discovered_urls),
                'forms': forms,
                'technologies': list(technologies),
                'pages_crawled': len(visited)
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            return f"Crawling error: {str(e)}"