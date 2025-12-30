#!/usr/bin/env python3
"""
IP Reputation Checker - Security Analyst Tool
Author: Asma
Description: Checks IP addresses against AbuseIPDB
"""

# import
import requests
import json
import sys

# Make API request
API_KEY = "Your API key here"
API_URL = "https://api.abuseipdb.com/api/v2/check"

print("✅ Security Tool Initialized!")
print(f"Target API: {API_URL}")

#HELPER FUNCTIONS

def is_valid_ip(ip_address):
    """
    Basic IP validation (simple version)
    Returns: True if looks like IPv4, False otherwise
    """
    parts = ip_address.split('.')
    if len(parts) != 4:
        return False
    
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    
    return True

def print_separator():
    """Print a visual separator line"""
    print("=" * 50)

#API CALLING FUNCTION

def check_single_ip(ip_address):
    """
    Check one IP against AbuseIPDB API
    Returns: Dictionary with results or None if error
    """
    print(f"\nChecking IP: {ip_address}")
    print_separator()
    
    # Prepare API request
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90
    }
    
    try:
        # Make the API call
        response = requests.get(API_URL, headers=headers, params=params, timeout=10)
        
        # Check if request was successful
        if response.status_code == 200:
            data = response.json()
            print("✅ API call successful!")
            return data.get('data')  # Return the actual IP data
        else:
            print(f"❌ API Error: Status code {response.status_code}")
            return None
            
    except requests.exceptions.Timeout:
        print("❌ Error: API request timed out")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

# Display output

def display_results(ip_data):
    """
    Format and display the IP investigation results
    """
    if not ip_data:
        print("No data to display")
        return
    
    print(f"IP Address:  {ip_data.get('ipAddress', 'N/A')}")
    print(f"Country:     {ip_data.get('countryName', 'N/A')}")
    print(f"ISP:         {ip_data.get('isp', 'N/A')}")
    print(f"Domain:      {ip_data.get('domain', 'N/A')}")
    
    score = ip_data.get('abuseConfidenceScore', 0)
    print(f"Abuse Score: {score}%")
    print(f"Total Reports: {ip_data.get('totalReports', 0)}")
    print(f"Last Reported: {ip_data.get('lastReportedAt', 'Never')}")
    
    # Threat assessment
    print("\n Threat Assessment:")
    if score >= 75:
        print("🚨 [Critical] - Known malicious IP")
    elif score >= 25:
        print("⚠️ [Warning] - Suspicious activity")
    else:
        print("✅ [Clean]- Likely legitimate")



def check_bulk_ips(filename):
    print(f" Function STARTED with filename: {filename}")
    """
    Check multiple IPs from a file
    """  
    try:
        print(f"About to open file") 
        print(f"Opening file...")  
        with open(filename, 'r') as file:
            ips = [line.strip() for line in file if line.strip()]
        print(f" Read {len(ips)} IPs: {ips}")
        
        print(f"\nProcessing {len(ips)} IPs from {filename}")
        print_separator()
        
        results = []
        for ip in ips:
            if is_valid_ip(ip):
                print(f"Checking: {ip}")
                if API_KEY != "YOUR_API_KEY_HERE":
                    ip_data = check_single_ip(ip)
                    if ip_data:
                        results.append({
                            'ip': ip,
                            'score': ip_data.get('abuseConfidenceScore', 0),
                            'country': ip_data.get('countryName', 'N/A'),
                            'isp': ip_data.get('isp', 'N/A')
                        })
                else:
                    print("❌ Please add your API key first!")
                    print("   Using demo data for now...")
                    # Add demo data instead of breaking
                    results.append({
                        'ip': ip,
                        'score': 50,  # Demo score
                        'country': 'Demo Country',
                        'isp': 'Demo ISP'
                    })
            else:
                print(f"Skipping invalid IP: {ip}")
        
        # Show summary
        if results:
            print("\n" + "="*60)
            print("BULK CHECK SUMMARY")
            print("="*60)
            for result in results:
                score = result['score']
                if score >= 75:
                    status = "🚨 HIGH"
                elif score >= 25:
                    status = "⚠️  MEDIUM"
                else:
                    status = "✅ LOW"
                print(f"{result['ip']} | {result['country']} | Score: {score}% | {status}")
            
            # Save to CSV
            save_to_csv(results, filename)
            
    except FileNotFoundError:
        print(f"❌ File not found: {filename}")
    except Exception as e:
        print(f"❌ Error: {e}")

def save_to_csv(results, original_filename):
    """
    Save results to CSV file
    """
    import csv
    from datetime import datetime
    
    # Create output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"results_{timestamp}.csv"
    
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Country', 'ISP', 'Score', 'Threat_Level', 'Timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            score = result['score']
            if score >= 75:
                threat = 'HIGH'
            elif score >= 25:
                threat = 'MEDIUM'
            else:
                threat = 'LOW'
                
            writer.writerow({
                'IP': result['ip'],
                'Country': result['country'],
                'ISP': result['isp'],
                'Score': score,
                'Threat_Level': threat,
                'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
    
    print(f"\n💾 Results saved to: {output_file}")

# INTERACTIVE MENU

def main_menu():
    """
    Main interactive menu for the tool
    """
    print("\n" + "="*60)
    print("        IP REPUTATION CHECKER - SECURITY ANALYST TOOL")
    print("        Author: Asma")
    print("="*60)
    
    print("\nAvailable Commands:")
    print("  check [IP]    - Check a single IP address")
    print("  bulk [file]   - Check multiple IPs from a file")
    print("  demo          - Show demo with sample data")
    print("  help          - Show this menu")
    print("  quit          - Exit the program")
    
    while True:
        try:
            command = input("\n🔍 Enter command: ").strip().lower()
            
            if command.startswith("check "):
                ip = command[6:]  # Get IP after "check "
                if is_valid_ip(ip):
                    if API_KEY != "YOUR_API_KEY_HERE":
                        ip_data = check_single_ip(ip)
                        if ip_data:
                            display_results(ip_data)
                    else:
                        print("❌ Please add your API key first!")
                        print("Get free key from: https://www.abuseipdb.com/account/api")
                        print("Then replace 'YOUR_API_KEY_HERE' in the code")
                else:
                    print("❌ Invalid IP format. Example: check 8.8.8.8")

            elif command.startswith("bulk "):
                filename = command[5:]  # Get filename after "bulk "
                if filename:
                    check_bulk_ips(filename)
                else:
                    print("❌ Please specify a file. Example: bulk ips.txt")
                    
                    
            elif command == "demo":
                print("\nDemo Mode - Sample Analysis:")
                mock_data = {
                    'ipAddress': '185.220.101.34',
                    'countryName': 'United Kingdom',
                    'isp': 'Asma Ejaz',
                    'domain': '[redacted].ru',
                    'abuseConfidenceScore': 100,
                    'totalReports': 124,
                    'lastReportedAt': '2025-12-30T10:15:30+00:00'
                }
                display_results(mock_data)
                
            elif command == "help":
                print("\n Available Commands:")
                print("  check [IP]    - Check a single IP address")
                print("  bulk [file]   - Check multiple IPs from a file")
                print("  demo          - Show demo with sample data")
                print("  help          - Show this menu")
                print("  quit          - Exit the program")
                
            elif command == "quit":
                print("\nI Hope it was useful...")
                break
                
            else:
                print("❌ Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print("\n\nInterrupted.")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

# TESTING
if __name__ == "__main__":
    print("\n" + "="*60)
    print("        IP REPUTATION CHECKER - TEST MODE")
    print("="*60)
    
    # Test 1: Helper functions
    print("\nTesting helper functions:")
    print(f"Valid IP 192.168.1.1: {is_valid_ip('192.168.1.1')}")
    print(f"Invalid IP 999.999.999.999: {is_valid_ip('999.999.999.999')}")
    
    # Test 2: API function structure (without real API key)
    print("\n🔧 Testing API function structure...")
    
    if API_KEY == "YOUR_API_KEY_HERE":
        print("\n⚠️  WARNING: Using placeholder API key")
        print("To test real API calls:")
        print("1. Get free key from: https://www.abuseipdb.com/account/api")
        print("2. Replace 'YOUR_API_KEY_HERE' with your actual key")
        print("3. Uncomment the test code below")
        
        # Demo with mock data
        print("\nDemo with mock data:")
        mock_data = {
            'ipAddress': '8.8.8.8',
            'countryName': 'Bahrain',
            'isp': 'Google LLC',
            'domain': 'google.com',
            'abuseConfidenceScore': 0,
            'totalReports': 7,
            'lastReportedAt': '2025-12-30T08:23:41+00:00'
        }
        display_results(mock_data)
        
    else:
        print("\n✅ Real API key detected!")
        print("Testing with Google's DNS server (8.8.8.8)...")
        ip_data = check_single_ip("8.8.8.8")
        if ip_data:
            display_results(ip_data)
    
    print_separator()
    
    # Ask if user wants to try interactive mode
    try:
        choice = input("\nOpen the main menu? (y/n): ").strip().lower()
        if choice == 'y':
            main_menu()
    except KeyboardInterrupt:
        print("\n\n Done!")
            
    except:
        pass
