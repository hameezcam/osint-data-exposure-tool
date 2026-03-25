import requests
import re

def check_domain_security(domain):
    """
    Check domain security using VirusTotal API
    ⚠️ SECURITY WARNING: API key is hardcoded - NOT recommended for production
    """
    # Input validation
    if not domain or not isinstance(domain, str):
        return {"error": "Invalid domain provided"}
    
    # Basic domain format validation
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        return {"error": "Invalid domain format"}
    
    # ⚠️ HARDCODED API KEY - INSECURE!
    VIRUSTOTAL_API_KEY = ""
    
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        print(f"Checking VirusTotal for domain: {domain}")
        response = requests.get(url, headers=headers, timeout=10)
        
        print(f"VirusTotal Response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            categories = attributes.get('categories', {})
            reputation = attributes.get('reputation', 0)
            
            result = {
                'domain': domain,
                'reputation_score': reputation,
                'security_metrics': {
                    'harmless': last_analysis_stats.get('harmless', 0),
                    'malicious': last_analysis_stats.get('malicious', 0),
                    'suspicious': last_analysis_stats.get('suspicious', 0),
                    'undetected': last_analysis_stats.get('undetected', 0)
                },
                'categories': categories,
                'total_vendors': sum(last_analysis_stats.values()),
                'last_analysis_date': attributes.get('last_analysis_date'),
                'whois': attributes.get('whois', '')[:500] + '...' if attributes.get('whois') else None
            }
            print(f"VirusTotal result: {result}")
            return result
        elif response.status_code == 404:
            return {"error": "Domain not found in VirusTotal database"}
        elif response.status_code == 429:
            return {"error": "VirusTotal API rate limit exceeded"}
        elif response.status_code == 401:
            return {"error": "Invalid VirusTotal API key"}
        elif response.status_code == 403:
            return {"error": "Access forbidden. Check API key permissions."}
        elif response.status_code >= 500:
            return {"error": f"VirusTotal server error: {response.status_code}"}
        else:
            return {"error": f"VirusTotal API error: {response.status_code}"}
            
    except requests.exceptions.Timeout:
        return {"error": "VirusTotal API timeout"}
    except requests.exceptions.ConnectionError:
        return {"error": "Network connection error"}
    except Exception as e:
        return {"error": f"Error checking VirusTotal: {str(e)}"}
