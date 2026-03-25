import requests
import re

def is_valid_ip(ip):
    """Validate IP address format"""
    ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    return ip_pattern.match(ip) is not None

def check_abuse(ip_list):
    """
    Checks AbuseIPDB for one or multiple IPs and returns structured results.
    """
    # Handle single IP input
    if isinstance(ip_list, str):
        ip_list = [ip_list]
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": "ABUSEIPDB_API_KEY"
    }

    results = []
    for ip in ip_list:
        try:
            # Validate IP format first
            if not is_valid_ip(ip):
                results.append({
                    "ipAddress": ip, 
                    "error": "Invalid IP address format"
                })
                continue

            params = {
                "ipAddress": ip, 
                "maxAgeInDays": "90",
                "verbose": True
            }
            
            print(f"Checking IP: {ip}")  # Debug print
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            print(f"Response status: {response.status_code}")  # Debug print
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                print(f"API Response: {data}")  # Debug print
                
                # Add the IP address to the result for easy identification
                data['ipAddress'] = ip
                results.append(data)
            elif response.status_code == 429:
                results.append({
                    "ipAddress": ip, 
                    "error": "Rate limit exceeded - try again later"
                })
            elif response.status_code == 401:
                results.append({
                    "ipAddress": ip, 
                    "error": "Invalid API key - check your AbuseIPDB API key"
                })
            else:
                results.append({
                    "ipAddress": ip, 
                    "error": f"API error: {response.status_code}",
                    "details": response.text[:100]  # First 100 chars of error
                })
                
        except requests.exceptions.Timeout:
            results.append({"ipAddress": ip, "error": "Request timeout"})
        except requests.exceptions.ConnectionError:
            results.append({"ipAddress": ip, "error": "Connection error"})
        except Exception as e:
            results.append({"ipAddress": ip, "error": f"Unexpected error: {str(e)}"})

    return results
