#!/usr/bin/env python3
"""
SIMPLE IP Checker API for Web Interface
Author: Asma
Purpose: Backend for web interface - uses same code as CLI tool
"""

import requests
import json
import os

# === SAME CODE FROM YOUR ip_checker.py ===
API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
API_URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip_for_web(ip_address):
    """Check IP - SIMPLIFIED version for web"""
    headers = {'Accept': 'application/json', 'Key': API_KEY}
    params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
    
    try:
        response = requests.get(API_URL, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()['data']
            
            # Same threat assessment as your CLI tool
            score = data.get('abuseConfidenceScore', 0)
            if score >= 75:
                threat = "🚨 MALICIOUS"
                emoji = "🚨"
            elif score >= 25:
                threat = "⚠️ SUSPICIOUS"
                emoji = "⚠️"
            else:
                threat = "✅ CLEAN"
                emoji = "✅"
            
            # Return SIMPLE results for web
            return {
                'ip': ip_address,
                'country': data.get('countryName', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'score': score,
                'reports': data.get('totalReports', 0),
                'lastReported': data.get('lastReportedAt', 'Never'),
                'threat': threat,
                'emoji': emoji,
                'status': 'success'
            }
        else:
            return {'error': f'API Error {response.status_code}', 'status': 'error'}
            
    except Exception as e:
        return {'error': str(e), 'status': 'error'}

# === SIMPLE WEB SERVER ===
from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Example: /check?ip=8.8.8.8
        if self.path.startswith('/check'):
            # Extract IP from URL
            ip = self.path.split('=')[1] if '=' in self.path else ''
            
            if not ip:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'No IP provided'}).encode())
                return
            
            # Check the IP (using YOUR existing logic!)
            result = check_ip_for_web(ip)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')  # Allow web to connect
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>IP Checker API is running!</h1>')
            
        else:
            self.send_response(404)
            self.end_headers()

def run_server():
    print("✅ Starting SIMPLE IP Checker API...")
    print("🌐 Web interface can connect to: http://localhost:8080")
    print("📡 Example: http://localhost:8080/check?ip=8.8.8.8")
    server = HTTPServer(('0.0.0.0', 8080), SimpleHandler)
    server.serve_forever()

if __name__ == '__main__':
    if not API_KEY:
        print("❌ ERROR: Set ABUSEIPDB_API_KEY environment variable!")
        print("   On Windows: set ABUSEIPDB_API_KEY=your_key_here")
        print("   On Mac/Linux: export ABUSEIPDB_API_KEY=your_key_here")
    else:
        run_server()
