#!/usr/bin/env python3
"""
API Security Toolkit v1.0 - Professional Edition
Complete with Cloud Support, CVSS 4.0, Rich Output, Proxy Support
Author: Kishan Khetia
License: MIT
"""

import argparse
import json
import re
import time
import sys
import os
import base64
import urllib.parse
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any

# Third-party imports
try:
    import requests
    import urllib3
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.tree import Tree
    from rich import box
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[+] Install with: pip install requests urllib3 rich")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Rich console
console = Console()


class CVSS40:
    """CVSS 4.0 Calculator"""
    
    @staticmethod
    def calculate(severity: str, exploitability: str = "HIGH") -> Tuple[float, str]:
        base_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.0
        }
        exploit_mods = {'HIGH': 1.0, 'MEDIUM': 0.8, 'LOW': 0.6}
        
        base = base_scores.get(severity, 5.0)
        modifier = exploit_mods.get(exploitability, 1.0)
        score = min(base * modifier, 10.0)
        
        if score >= 9.0:
            rating = "Critical"
        elif score >= 7.0:
            rating = "High"
        elif score >= 4.0:
            rating = "Medium"
        else:
            rating = "Low"
            
        return round(score, 1), rating


class CloudAPITester:
    """Cloud API Security Testing"""
    
    CLOUD_SIGNATURES = {
        'aws': {
            'headers': ['x-amz-', 'x-amzn-', 'aws-'],
            'endpoints': ['amazonaws.com', 'aws.amazon.com'],
            'patterns': ['aws_access_key_id', 'arn:aws:']
        },
        'azure': {
            'headers': ['x-ms-', 'azure-', 'x-ms-version'],
            'endpoints': ['azure.com', 'windows.net', 'azurewebsites.net'],
            'patterns': ['subscription_id', 'tenant_id']
        },
        'gcp': {
            'headers': ['x-goog-', 'x-gcloud-'],
            'endpoints': ['googleapis.com', 'cloud.google.com', 'appspot.com'],
            'patterns': ['project_id', 'gcp_access_token']
        }
    }
    
    @staticmethod
    def detect_provider(response_headers: Dict, url: str) -> Optional[str]:
        url_lower = url.lower()
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        
        for provider, sigs in CloudAPITester.CLOUD_SIGNATURES.items():
            for endpoint in sigs['endpoints']:
                if endpoint in url_lower:
                    return provider
            for header in sigs['headers']:
                for h in headers_lower:
                    if header in h:
                        return provider
        return None
    
    @staticmethod
    def get_tests(provider: str) -> List[Dict]:
        tests = {
            'aws': [
                {
                    'name': 'AWS Metadata SSRF',
                    'path': 'http://169.254.169.254/latest/meta-data/',
                    'method': 'GET',
                    'severity': 'CRITICAL',
                    'cvss': 9.8,
                    'type': 'SSRF'
                },
                {
                    'name': 'S3 Bucket Public',
                    'path': '/?list-type=2',
                    'method': 'GET',
                    'severity': 'CRITICAL',
                    'cvss': 9.1,
                    'type': 'BOLA'
                }
            ],
            'azure': [
                {
                    'name': 'Azure Metadata SSRF',
                    'path': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                    'method': 'GET',
                    'headers': {'Metadata': 'true'},
                    'severity': 'CRITICAL',
                    'cvss': 9.8,
                    'type': 'SSRF'
                }
            ],
            'gcp': [
                {
                    'name': 'GCP Metadata SSRF',
                    'path': 'http://metadata.google.internal/computeMetadata/v1/',
                    'method': 'GET',
                    'headers': {'Metadata-Flavor': 'Google'},
                    'severity': 'CRITICAL',
                    'cvss': 9.8,
                    'type': 'SSRF'
                }
            ]
        }
        return tests.get(provider, [])


class APISecurityToolkit:
    """Professional API Security Toolkit"""
    
    def __init__(self, target: str, auth_token: Optional[str] = None, 
                 headers: Optional[Dict] = None, output_dir: str = '.',
                 proxy: Optional[str] = None, timeout: int = 10):
        self.target = target.rstrip('/')
        self.auth_token = auth_token
        self.headers = headers or {
            'User-Agent': 'API-Security-Toolkit/4.0',
            'Accept': 'application/json'
        }
        if auth_token:
            self.headers['Authorization'] = f"Bearer {auth_token}"
        
        self.output_dir = output_dir
        self.timeout = timeout
        self.proxy = proxy
        self.proxies = {'http': proxy, 'https': proxy} if proxy else None
        
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.discovered_endpoints = []
        self.vulnerabilities = []
        self.tested_endpoints = set()
        self.recon_data = {}
        self.cloud_provider = None
        
        self.stats = {
            'requests_made': 0,
            'start_time': time.time()
        }
    
    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = urllib.parse.urljoin(self.target, path)
        kwargs.setdefault('headers', self.headers)
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', False)
        
        if self.proxies:
            kwargs['proxies'] = self.proxies
        
        self.stats['requests_made'] += 1
        return requests.request(method, url, **kwargs)
    
    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║     API Security Toolkit v1.0 - Professional Edition             ║
║          Cloud Ready | CVSS 4.0 | OWASP Top 10                   ║
╚══════════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold blue", box=box.DOUBLE))
        console.print(f"[bold]Target:[/bold] {self.target}")
        console.print(f"[bold]Time:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if self.proxy:
            console.print(f"[bold]Proxy:[/bold] {self.proxy}")
        console.print()
    
    def run_recon(self, save_file: Optional[str] = None) -> Dict:
        self.print_banner()
        console.print("[bold yellow]🔍 PHASE 1: RECONNAISSANCE[/bold yellow]\\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task1 = progress.add_task("[cyan]Discovering API docs...", total=None)
            self._check_api_docs()
            progress.update(task1, completed=True)
            
            task2 = progress.add_task("[cyan]Fuzzing endpoints...", total=None)
            self._fuzz_common_endpoints()
            progress.update(task2, completed=True)
            
            task3 = progress.add_task("[cyan]Fingerprinting tech...", total=None)
            self._analyze_tech_stack()
            progress.update(task3, completed=True)
            
            task4 = progress.add_task("[cyan]Detecting cloud provider...", total=None)
            self._detect_cloud()
            progress.update(task4, completed=True)
            
            task5 = progress.add_task("[cyan]Testing CORS...", total=None)
            self._check_cors()
            progress.update(task5, completed=True)
        
        self._display_recon_results()
        
        report = self._generate_recon_report()
        
        output_file = save_file or f"{self.output_dir}/recon_report_{self.timestamp}.json"
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        console.print(f"\\n[bold green]✅ Recon Complete[/bold green] - [dim]{output_file}[/dim]\\n")
        return report
    
    def _check_api_docs(self):
        doc_paths = [
            '/swagger.json', '/swagger-ui.html', '/api-docs', '/openapi.json',
            '/v2/api-docs', '/v3/api-docs', '/api/swagger.json', '/docs',
            '/redoc', '/api.html', '/openapi.yaml', '/.well-known/openapi.json'
        ]
        
        for path in doc_paths:
            try:
                resp = self._request('GET', path)
                if resp.status_code == 200:
                    try:
                        spec = resp.json()
                        for p, methods in spec.get('paths', {}).items():
                            for m in methods.keys():
                                if m in ['get', 'post', 'put', 'delete', 'patch']:
                                    self.discovered_endpoints.append({
                                        'path': p, 'method': m.upper(),
                                        'source': 'openapi', 'status_code': 200
                                    })
                    except:
                        pass
                    return
            except:
                continue
    
    def _fuzz_common_endpoints(self):
        common_paths = [
            '/api/v1/users', '/api/v1/admin', '/api/v1/login', '/api/v1/register',
            '/api/v2/users', '/api/users', '/api/admin', '/api/login',
            '/api/health', '/api/status', '/api/config', '/api/settings',
            '/api/v1/orders', '/api/v1/products', '/graphql', '/api/graphql',
            '/api/v1/profile', '/api/v1/account', '/api/v1/me',
            '/api/v1/search', '/api/v1/export', '/api/v1/import',
            '/actuator/health', '/actuator/info', '/actuator/env',
            '/.env', '/config.json', '/api/config.json'
        ]
        
        for path in common_paths:
            try:
                resp = self._request('GET', path, allow_redirects=False)
                if resp.status_code != 404:
                    self.discovered_endpoints.append({
                        'path': path, 'method': 'GET',
                        'status_code': resp.status_code,
                        'size': len(resp.content),
                        'source': 'fuzz'
                    })
            except:
                continue
    
    def _analyze_tech_stack(self):
        try:
            resp = self._request('GET', '/')
            stack = {
                'server': resp.headers.get('Server', 'Unknown'),
                'framework': 'Unknown'
            }
            
            body = resp.text.lower()
            if 'laravel' in body:
                stack['framework'] = 'Laravel/PHP'
            elif 'express' in body:
                stack['framework'] = 'Express.js/Node'
            elif 'django' in body:
                stack['framework'] = 'Django/Python'
            elif 'spring' in body:
                stack['framework'] = 'Spring Boot/Java'
            elif 'rails' in body:
                stack['framework'] = 'Ruby on Rails'
            
            self.recon_data['tech_stack'] = stack
        except:
            pass
    
    def _detect_cloud(self):
        try:
            resp = self._request('GET', '/')
            provider = CloudAPITester.detect_provider(resp.headers, self.target)
            if provider:
                self.cloud_provider = provider
                self.recon_data['cloud_provider'] = provider
        except:
            pass
    
    def _check_cors(self):
        try:
            headers = {**self.headers, 'Origin': 'https://evil.com'}
            resp = self._request('OPTIONS', '/', headers=headers)
            
            allow_origin = resp.headers.get('Access-Control-Allow-Origin', '')
            allow_creds = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            if allow_origin == 'https://evil.com':
                self.recon_data['cors_issue'] = {
                    'severity': 'HIGH' if allow_creds.lower() == 'true' else 'MEDIUM',
                    'origin': allow_origin,
                    'credentials': allow_creds
                }
        except:
            pass
    
    def _display_recon_results(self):
        if not self.discovered_endpoints:
            console.print("[yellow]⚠️  No endpoints discovered[/yellow]\\n")
            return
        
        table = Table(title=f"Discovered Endpoints ({len(self.discovered_endpoints)})", box=box.ROUNDED)
        table.add_column("Method", style="cyan", no_wrap=True)
        table.add_column("Path", style="magenta")
        table.add_column("Status", justify="center")
        table.add_column("Size", justify="right")
        table.add_column("Source", style="dim")
        
        for ep in self.discovered_endpoints[:20]:
            status = ep.get('status_code', ep.get('status', 'Unknown'))
            status_style = "green" if status == 200 else "yellow" if status in [401, 403] else "red"
            
            table.add_row(
                ep.get('method', 'GET'),
                ep.get('path', '/')[:50],
                f"[{status_style}]{status}[/{status_style}]",
                str(ep.get('size', 0)),
                ep.get('source', 'unknown')
            )
        
        if len(self.discovered_endpoints) > 20:
            table.add_row("...", f"+{len(self.discovered_endpoints) - 20} more", "", "", "")
        
        console.print(table)
        console.print()
        
        # Info panels
        if self.recon_data.get('tech_stack'):
            tech = self.recon_data['tech_stack']
            console.print(Panel(
                f"[bold]Server:[/bold] {tech.get('server', 'Unknown')}\\n"
                f"[bold]Framework:[/bold] {tech.get('framework', 'Unknown')}",
                title="Technology Stack",
                border_style="blue",
                box=box.ROUNDED
            ))
        
        if self.cloud_provider:
            console.print(Panel(
                f"[bold cyan]☁️  {self.cloud_provider.upper()}[/bold cyan] detected!\\n"
                "Cloud-specific tests will be included.",
                title="Cloud Provider",
                border_style="cyan",
                box=box.ROUNDED
            ))
        console.print()
    
    def _generate_recon_report(self) -> Dict:
        return {
            'scan_type': 'reconnaissance',
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_endpoints': len(self.discovered_endpoints),
                'requests_made': self.stats['requests_made'],
                'cloud_provider': self.cloud_provider
            },
            'endpoints': self.discovered_endpoints,
            'tech_stack': self.recon_data.get('tech_stack', {}),
            'cors': self.recon_data.get('cors_issue', {})
        }
    
    def run_va(self, recon_file: Optional[str] = None, 
               endpoints: Optional[List[Dict]] = None,
               save_file: Optional[str] = None) -> Dict:
        console.print("[bold red]🛡️  PHASE 2: VULNERABILITY ASSESSMENT[/bold red]\\n")
        
        if recon_file:
            with open(recon_file, 'r') as f:
                data = json.load(f)
                self.discovered_endpoints = data.get('endpoints', [])
                self.cloud_provider = data.get('summary', {}).get('cloud_provider')
        elif endpoints:
            self.discovered_endpoints = endpoints
        else:
            console.print("[red]❌ No endpoints provided[/red]\\n")
            return {}
        
        console.print(f"[dim]Testing {len(self.discovered_endpoints)} endpoints...[/dim]\\n")
        
        # JWT Analysis
        if self.auth_token and self.auth_token.startswith('eyJ'):
            self._analyze_jwt()
        
        # Cloud-specific tests
        if self.cloud_provider:
            self._run_cloud_tests()
        
        # Test each endpoint
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("[red]Scanning...", total=len(self.discovered_endpoints))
            
            for ep in self.discovered_endpoints:
                method = ep.get('method', 'GET')
                path = ep.get('path', '/')
                progress.update(task, description=f"[red]Testing {method} {path[:40]}...")
                self._test_endpoint(method, path)
                progress.advance(task)
        
        # Calculate CVSS
        for vuln in self.vulnerabilities:
            if 'cvss' not in vuln:
                score, rating = CVSS40.calculate(vuln['severity'])
                vuln['cvss'] = score
                vuln['cvss_rating'] = rating
        
        self._display_va_results()
        
        report = self._generate_va_report()
        
        output_file = save_file or f"{self.output_dir}/va_report_{self.timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self._generate_html_report(report)
        
        console.print(f"[bold green]✅ VA Complete[/bold green]")
        console.print(f"[dim]JSON: {output_file}[/dim]")
        console.print(f"[dim]HTML: {output_file.replace('.json', '.html')}[/dim]\\n")
        
        return report
    
    def _analyze_jwt(self):
        try:
            parts = self.auth_token.split('.')
            if len(parts) != 3:
                return
            
            # helper to add padding
            def _pad(s: str) -> bytes:
                padding = '=' * (-len(s) % 4)
                return base64.b64decode(s + padding)

            header = json.loads(_pad(parts[0]))
            payload = json.loads(_pad(parts[1]))
            
            if header.get('alg') == 'none':
                self.vulnerabilities.append({
                    'type': 'JWT None Algorithm',
                    'severity': 'CRITICAL',
                    'cvss': 9.8,
                    'endpoint': 'JWT Token',
                    'description': 'JWT accepts "none" algorithm',
                    'remediation': 'Explicitly specify allowed algorithms'
                })
            
            if 'exp' not in payload:
                self.vulnerabilities.append({
                    'type': 'JWT No Expiration',
                    'severity': 'HIGH',
                    'cvss': 7.5,
                    'endpoint': 'JWT Token',
                    'description': 'JWT has no expiration claim',
                    'remediation': 'Add exp claim with short validity'
                })
        except:
            pass
    
    def _run_cloud_tests(self):
        if not self.cloud_provider:
            return
        
        tests = CloudAPITester.get_tests(self.cloud_provider)
        for test in tests:
            try:
                headers = test.get('headers', {})
                resp = self._request(test['method'], test['path'], headers=headers)
                
                if resp.status_code == 200:
                    self.vulnerabilities.append({
                        'type': f"Cloud: {test['name']}",
                        'severity': test['severity'],
                        'cvss': test['cvss'],
                        'endpoint': test['path'],
                        'description': f"{test['type']} vulnerability in cloud environment",
                        'remediation': 'Restrict access to metadata services'
                    })
            except:
                pass
    
    def _test_endpoint(self, method: str, path: str):
        key = f"{method}:{path}"
        if key in self.tested_endpoints:
            return
        self.tested_endpoints.add(key)
        
        # BOLA/IDOR
        if any(ind in path.lower() for ind in ['user', 'order', 'account', 'profile']):
            # fix regex to match digits rather than literal "\d+"
            test_path = re.sub(r'/(\d+)(/|$)', lambda m: f'/{int(m.group(1))+1}{m.group(2)}', path)
            if test_path != path:
                try:
                    resp = self._request(method, test_path)
                    if resp.status_code == 200 and len(resp.content) > 100:
                        self.vulnerabilities.append({
                            'type': 'BOLA/IDOR',
                            'severity': 'CRITICAL',
                            'cvss': 9.1,
                            'endpoint': f"{method} {path}",
                            'description': f'IDOR: {test_path} accessible',
                            'remediation': 'Implement object-level authorization'
                        })
                except:
                    pass
        
        # Data Exposure
        try:
            resp = self._request(method, path)
            if resp.status_code == 200:
                text = resp.text.lower()
                sensitive = ['password', 'secret', 'private_key', 'credit_card']
                found = [s for s in sensitive if s in text]
                if found:
                    self.vulnerabilities.append({
                        'type': 'Data Exposure',
                        'severity': 'HIGH',
                        'cvss': 7.5,
                        'endpoint': f"{method} {path}",
                        'description': f'Sensitive fields: {", ".join(found)}',
                        'remediation': 'Filter sensitive data'
                    })
                
                # Rate limiting
                responses = []
                for _ in range(3):
                    try:
                        r = self._request(method, path, timeout=3)
                        responses.append(r.status_code)
                    except:
                        pass
                if all(r == 200 for r in responses):
                    self.vulnerabilities.append({
                        'type': 'No Rate Limiting',
                        'severity': 'MEDIUM',
                        'cvss': 5.3,
                        'endpoint': f"{method} {path}",
                        'description': 'No rate limiting detected',
                        'remediation': 'Implement rate limiting'
                    })
        except:
            pass
        
        # Admin bypass
        if '/admin/' in path.lower():
            try:
                resp = self._request(method, path)
                if resp.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Admin Bypass',
                        'severity': 'CRITICAL',
                        'cvss': 8.8,
                        'endpoint': f"{method} {path}",
                        'description': 'Admin endpoint accessible',
                        'remediation': 'Implement RBAC'
                    })
            except:
                pass
        
        # Mass Assignment
        if method in ['POST', 'PUT']:
            for field in [{'is_admin': True}, {'role': 'admin'}]:
                try:
                    resp = self._request(method, path, json=field)
                    if resp.status_code in [200, 201]:
                        self.vulnerabilities.append({
                            'type': 'Mass Assignment',
                            'severity': 'CRITICAL',
                            'cvss': 9.1,
                            'endpoint': f"{method} {path}",
                            'description': f'Accepts {list(field.keys())[0]}',
                            'remediation': 'Use allowlists'
                        })
                        break
                except:
                    continue
        
        # Security Headers
        try:
            resp = self._request(method, path)
            for header in ['X-Content-Type-Options', 'X-Frame-Options']:
                if header not in resp.headers:
                    self.vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': 'MEDIUM',
                        'cvss': 5.0,
                        'endpoint': f"{method} {path}",
                        'description': f'Missing {header}',
                        'remediation': f'Add {header}'
                    })
        except:
            pass
        
        # SQL Injection
        try:
            test_path = f"{path}?q=' OR '1'='1"
            resp = self._request(method, test_path)
            if any(x in resp.text.lower() for x in ['sql', 'syntax error']):
                self.vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'CRITICAL',
                    'cvss': 9.8,
                    'endpoint': f"{method} {path}",
                    'description': 'SQL error triggered',
                    'remediation': 'Use parameterized queries'
                })
        except:
            pass
        
        # Old versions
        for old in [path.replace('/v2/', '/v1/'), path.replace('/api/v1/', '/api/beta/')]:
            if old != path:
                try:
                    resp = self._request('GET', old)
                    if resp.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Old API Version',
                            'severity': 'HIGH',
                            'cvss': 7.5,
                            'endpoint': f"GET {path}",
                            'description': f'Old version: {old}',
                            'remediation': 'Retire old versions'
                        })
                        break
                except:
                    pass
    
    def _display_va_results(self):
        if not self.vulnerabilities:
            console.print("[bold green]✅ No vulnerabilities detected![/bold green]\\n")
            return
        
        severity_counts = defaultdict(int)
        for v in self.vulnerabilities:
            severity_counts[v['severity']] += 1
        
        summary_table = Table(title="Vulnerability Summary", show_header=False, box=box.ROUNDED)
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        
        for sev, color in [('CRITICAL', 'red'), ('HIGH', 'yellow'), ('MEDIUM', 'blue'), ('LOW', 'green')]:
            if severity_counts[sev] > 0:
                summary_table.add_row(f"[{color}]{sev}[/{color}]", str(severity_counts[sev]))
        
        console.print(summary_table)
        console.print()
        
        table = Table(title=f"Vulnerabilities ({len(self.vulnerabilities)} found)", box=box.ROUNDED)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("CVSS", justify="center", width=6)
        table.add_column("Type", style="cyan")
        table.add_column("Endpoint", style="magenta")
        
        sorted_vulns = sorted(self.vulnerabilities, key=lambda x: x.get('cvss', 0), reverse=True)
        
        for vuln in sorted_vulns[:20]:
            severity = vuln['severity']
            color = 'red' if severity == 'CRITICAL' else 'yellow' if severity == 'HIGH' else 'blue'
            cvss = vuln.get('cvss', 'N/A')
            
            table.add_row(
                f"[{color}]{severity}[/{color}]",
                str(cvss),
                vuln['type'][:30],
                vuln['endpoint'][:40]
            )
        
        console.print(table)
        console.print()
        
        critical = [v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']
        if critical:
            console.print(Panel(
                f"[bold red]⚠️  {len(critical)} CRITICAL vulnerabilities found![/bold red]",
                title="Critical Alert",
                border_style="red",
                box=box.DOUBLE
            ))
    
    def _generate_va_report(self) -> Dict:
        severity_counts = defaultdict(int)
        for v in self.vulnerabilities:
            severity_counts[v['severity']] += 1
        
        return {
            'scan_type': 'vulnerability_assessment',
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'endpoints_tested': len(self.tested_endpoints),
                'vulnerabilities_found': len(self.vulnerabilities),
                'severity_counts': dict(severity_counts)
            },
            'vulnerabilities': self.vulnerabilities
        }
    
    def _generate_html_report(self, report: Dict):
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>API Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .vulnerability {{ border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; background: #fff5f5; }}
        .vulnerability.critical {{ border-color: #dc3545; }}
        .vulnerability.high {{ border-color: #ffc107; }}
        .severity {{ font-weight: bold; text-transform: uppercase; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #ffc107; }}
        .cvss {{ background: #333; color: white; padding: 3px 8px; border-radius: 3px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #007bff; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 API Security Assessment Report</h1>
        <p><strong>Target:</strong> {report['target']}</p>
        <p><strong>Generated:</strong> {report['timestamp']}</p>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>Endpoints Tested:</strong> {report['summary']['endpoints_tested']}</p>
            <p><strong>Vulnerabilities Found:</strong> {report['summary']['vulnerabilities_found']}</p>
        </div>
        
        <h2>Findings</h2>
"""
        
        for vuln in report['vulnerabilities']:
            severity_class = vuln['severity'].lower()
            cvss = vuln.get('cvss', 'N/A')
            html += f"""
        <div class="vulnerability {severity_class}">
            <span class="severity {severity_class}">{vuln['severity']}</span>
            <span class="cvss">CVSS: {cvss}</span>
            <h3>{vuln['type']}</h3>
            <p><strong>Endpoint:</strong> {vuln['endpoint']}</p>
            <p><strong>Description:</strong> {vuln['description']}</p>
            <p><strong>Remediation:</strong> {vuln['remediation']}</p>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        output_file = f"{self.output_dir}/va_report_{self.timestamp}.html"
        with open(output_file, 'w') as f:
            f.write(html)
    
    def run_full_pipeline(self):
        recon = self.run_recon()
        
        if not self.discovered_endpoints:
            console.print("[red]❌ No endpoints found, stopping.[/red]\\n")
            return None
        
        va = self.run_va(endpoints=self.discovered_endpoints)
        
        combined = {
            'scan_type': 'full_assessment',
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'recon': recon,
            'va': va
        }
        
        output_file = f"{self.output_dir}/full_assessment_{self.timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(combined, f, indent=2)
        
        elapsed = time.time() - self.stats['start_time']
        console.print(Panel(
            f"[bold green]🎯 Full Assessment Complete[/bold green]\\n\\n"
            f"Endpoints: {len(self.discovered_endpoints)}\\n"
            f"Vulnerabilities: {len(self.vulnerabilities)}\\n"
            f"Requests: {self.stats['requests_made']}\\n"
            f"Time: {elapsed:.1f}s",
            title="Summary",
            border_style="green",
            box=box.DOUBLE
        ))
        
        return combined


def main():
    parser = argparse.ArgumentParser(
        description='🔍 API Security Toolkit v1.0 - Cloud Ready | CVSS 4.0 | OWASP Top 10',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python api_security_toolkit.py -t https://api.example.com
  
  # With proxy (Burp Suite)
  python api_security_toolkit.py -t https://api.example.com --proxy http://127.0.0.1:8080
  
  # Cloud API (AWS)
  python api_security_toolkit.py -t https://xxx.execute-api.amazonaws.com/prod
  
  # With authentication
  python api_security_toolkit.py -t https://api.example.com -k "eyJhbG..."
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target API URL')
    parser.add_argument('-m', '--mode', choices=['recon', 'va', 'full'], default='full')
    parser.add_argument('-r', '--recon-file', help='Recon report for VA mode')
    parser.add_argument('-e', '--endpoint', help='Specific endpoint (METHOD:/path)')
    parser.add_argument('-k', '--token', help='Auth token/JWT')
    parser.add_argument('-o', '--output', default='.', help='Output directory')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    
    args = parser.parse_args()
    
    toolkit = APISecurityToolkit(
        target=args.target,
        auth_token=args.token,
        output_dir=args.output,
        proxy=args.proxy,
        timeout=args.timeout
    )
    
    try:
        if args.mode == 'recon':
            toolkit.run_recon()
        elif args.mode == 'va':
            if args.endpoint:
                method, path = args.endpoint.split(':', 1)
                toolkit.run_va(endpoints=[{'method': method.upper(), 'path': path}])
            else:
                toolkit.run_va(recon_file=args.recon_file)
        elif args.mode == 'full':
            toolkit.run_full_pipeline()
    except KeyboardInterrupt:
        console.print("\\n[red]❌ Interrupted[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()

