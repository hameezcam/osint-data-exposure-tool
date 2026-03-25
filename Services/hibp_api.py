HIBP_API_KEY = ""
import requests
import time
from typing import Dict, List, Optional

def check_breach(email):
    """Check if an email has been involved in data breaches"""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "OSINT-Exposure-Dashboard",
        "Accept": "application/json"
    }
    
    params = {
        "truncateResponse": False,
        "includeUnverified": True
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            breaches = response.json()
            return {
                "email": email,
                "breach_count": len(breaches),
                "breaches": breaches,
                "status": "breached"
            }
        elif response.status_code == 404:
            return {
                "email": email,
                "breach_count": 0,
                "breaches": [],
                "status": "safe"
            }
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded. Please wait before making more requests."}
        else:
            return {"error": f"API error: {response.status_code} - {response.text}"}
            
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}

def check_multiple_emails(emails: List[str], delay: float = 1.6) -> List[Dict]:
    """
    Check multiple email addresses for breaches with rate limiting
    
    Args:
        emails (List[str]): List of email addresses to check
        delay (float): Delay between requests in seconds (HIBP requires 1.6s between requests)
        
    Returns:
        List[Dict]: Results for each email
    """
    results = []
    
    for email in emails:
        result = check_breach(email)
        results.append(result)
        
        # Respect HIBP rate limits (1.5-2 seconds between requests)
        time.sleep(delay)
        
    return results

def get_breach_details(breach_name: str) -> Optional[Dict]:
    """
    Get detailed information about a specific breach
    
    Args:
        breach_name (str): Name of the breach
        
    Returns:
        Dict: Breach details
    """
    url = f"https://haveibeenpwned.com/api/v3/breach/{breach_name}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "OSINT-Exposure-Dashboard"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except requests.exceptions.RequestException:
        return None

def check_pastebin_account(email: str) -> Dict:
    """
    Check if email appears in Pastebin pastes
    
    Args:
        email (str): Email address to check
        
    Returns:
        Dict: Pastebin results
    """
    url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "OSINT-Exposure-Dashboard"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            pastes = response.json()
            return {
                "email": email,
                "paste_count": len(pastes),
                "pastes": pastes,
                "status": "found_in_pastes"
            }
        elif response.status_code == 404:
            return {
                "email": email,
                "paste_count": 0,
                "pastes": [],
                "status": "not_found_in_pastes"
            }
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded"}
        else:
            return {"error": f"API error: {response.status_code}"}
            
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
