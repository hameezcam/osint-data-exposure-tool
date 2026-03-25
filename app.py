from flask import Flask, request, render_template, redirect, url_for, session, jsonify, flash
from services.hibp_api import check_breach, check_multiple_emails, check_pastebin_account
from services.abuseipdb_api import check_abuse
from services.virustotal_api import check_domain_security
from analysis.nlp_processor import extract_sensitive_info
from database import init_db, register_user, validate_user
from analysis.password_strength import calculate_password_strength, generate_strong_password
from analysis.scraper import WebScraper, quick_scrape, scrape_multiple_sources, extract_data_for_analysis
import time, os, secrets
from datetime import datetime
from functools import wraps

init_db()
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
password_check_attempts = {}

def rate_limit_password_checks(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        current_time = time.time()
        password_check_attempts[client_ip] = [t for t in password_check_attempts.get(client_ip, []) if current_time - t < 3600]
        if len(password_check_attempts.get(client_ip, [])) >= 100:
            return jsonify({"error": "Rate limit exceeded. Please try again later.", "score": 0, "text": "Rate Limited", "feedback":
                            ["Too many password check requests. Please wait."]}), 429
        password_check_attempts.setdefault(client_ip, []).append(current_time)
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def sanitize_sample_data():
    return {
        "source":"Sample exposed data for testing:\nEmail: test@example.com found in logs\nServer IP: 192.168.1.1 with open ports\nDatabase connection: 10.0.0.5:3306\nAdmin login: admin@company.org",
        "extracted": {
            "emails": ["test@example.com", "admin@company.org"],
            "ips": ["192.168.1.1", "10.0.0.5"],
            "passwords": [],
            "api_keys": []
        },
        "scraped_count": 3,
        "note": "This is sample data for demonstration purposes",
        "is_sample_data": True
    }

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    
    data = request.get_json()
    username, password = data.get("username"), data.get("password")
    
    # Get client IP address
    client_ip = request.remote_addr
    
    # Validate user with IP tracking
    success, result = validate_user(username, password, client_ip, request.headers.get('User-Agent'))
    
    if success:
        session.permanent = True
        session["user"] = username
        session.pop('_flashes', None)
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": result})

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "No data received."})
        
        username, email, password = data.get("username"), data.get("email"), data.get("password")
        
        if not username or not email or not password:
            return jsonify({"success": False, "message": "Username, email and password are required!"})
        
        # Check password strength
        password_strength = calculate_password_strength(password)
        if password_strength["score"] < 2:
            return jsonify({
                "success": False, 
                "message": "Password is too weak. Please choose a stronger password.", 
                "password_feedback": password_strength["feedback"]
            })
        
        if password_strength["exposed"]:
            return jsonify({
                "success": False, 
                "message": "This password has been exposed in data breaches. Please choose a different password.", 
                "breach_count": password_strength["breach_count"]
            })
        
        # Attempt to register user
        success, message = register_user(username, email, password)
        
        if success:
            session.permanent = True
            session["user"] = username
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "message": message})
            
    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"})

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["user"])

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route("/api/password_strength", methods=["POST"])
@rate_limit_password_checks
def api_password_strength():
    try:
        data = request.get_json()
        password = data.get("password", "")
        if not password:
            return jsonify({"score": 0, "text": "Very Weak", "feedback": ["Please enter a password to analyze"], "entropy": 0, "exposed": False, "breach_count": 0})
        if len(password) > 256:
            return jsonify({"score": 0, "text": "Invalid", "feedback": ["Password is too long (maximum 256 characters)"], "entropy": 0, "exposed": False, "breach_count": 0})
        return jsonify(calculate_password_strength(password))
    except Exception as e:
        app.logger.error(f"Password strength check error: {str(e)}")
        return jsonify({"score": 0, "text": "Error", "feedback": ["Unable to analyze password at this time"], "entropy": 0, "exposed": False, "breach_count": 0}), 500

@app.route("/api/email_breach", methods=["POST"])
@login_required
def api_email_breach():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        if not email:
            return jsonify({"error": "Email is required"}), 400
        if '@' not in email:
            return jsonify({"error": "Invalid email format"}), 400
        result = check_breach(email)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Error checking email: {str(e)}"}), 500

@app.route("/api/email_pastebin", methods=["POST"])
@login_required
def api_email_pastebin():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        if not email:
            return jsonify({"error": "Email is required"}), 400
        if '@' not in email:
            return jsonify({"error": "Invalid email format"}), 400
        result = check_pastebin_account(email)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Error checking pastebin: {str(e)}"}), 500

@app.route("/api/bulk_email_check", methods=["POST"])
@login_required
def api_bulk_email_check():
    try:
        data = request.get_json()
        emails_text = data.get('emails', '')
        if not emails_text:
            return jsonify({"error": "Emails are required"}), 400
        emails = []
        for line in emails_text.split('\n'):
            for email in line.split(','):
                email = email.strip().lower()
                if email and '@' in email:
                    emails.append(email)
        if not emails:
            return jsonify({"error": "No valid emails found"}), 400
        if len(emails) > 5:
            return jsonify({"error": "Maximum 5 emails per request"}), 400
        results = check_multiple_emails(emails)
        total_emails = len(results)
        breached_emails = sum(1 for r in results if r.get('status') == 'breached')
        safe_emails = total_emails - breached_emails
        total_breaches = sum(r.get('breach_count', 0) for r in results if r.get('status') == 'breached')
        return jsonify({'results': results, 'total_checked': total_emails, 'breached_emails': breached_emails, 'safe_emails': safe_emails, 'total_breaches': total_breaches})
    except Exception as e:
        return jsonify({"error": f"Error checking emails: {str(e)}"}), 500

@app.route("/api/scrape", methods=["POST"])
@login_required
def api_scrape():
    """Scrape a single URL"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            return jsonify({"error": "Invalid URL format. Must start with http:// or https://"}), 400
        
        result = quick_scrape(url)
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Scraping error: {str(e)}")
        return jsonify({"error": f"Scraping failed: {str(e)}"}), 500

@app.route("/api/scrape_url", methods=["POST"])
@login_required
def api_scrape_url():
    """Scrape a single URL and analyze for sensitive information"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        selectors = data.get('selectors', [])
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            return jsonify({"error": "Invalid URL format. Must start with http:// or https://"}), 400
        
        # Use WebScraper for more control
        scraper = WebScraper()
        result = scraper.scrape_url(url, selectors=selectors if selectors else None)
        
        # Extract sensitive information
        analysis_result = {}
        if result.get('success'):
            analysis_result = extract_sensitive_info(result.get('text_content', ''))
        
        return jsonify({
            "scraping": result,
            "analysis": analysis_result
        })
        
    except Exception as e:
        app.logger.error(f"Scraping error: {str(e)}")
        return jsonify({"error": f"Scraping failed: {str(e)}"}), 500

@app.route("/api/bulk_scrape", methods=["POST"])
@login_required
def api_bulk_scrape():
    """Scrape multiple URLs and analyze for sensitive information"""
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls or not isinstance(urls, list):
            return jsonify({"error": "URLs list is required"}), 400
        
        if len(urls) > 5:  # Limit for safety
            return jsonify({"error": "Maximum 5 URLs per request"}), 400
        
        # Validate each URL
        valid_urls = []
        for url in urls:
            url = url.strip()
            if url.startswith(('http://', 'https://')):
                valid_urls.append(url)
        
        if not valid_urls:
            return jsonify({"error": "No valid URLs provided"}), 400
        
        # Scrape all URLs
        results = scrape_multiple_sources(valid_urls)
        
        # Analyze each result and prepare response
        scraping_results = []
        successful_scrapes = 0
        
        for result in results:
            analysis_result = {}
            if result.get('success'):
                analysis_result = extract_sensitive_info(result.get('text_content', ''))
                successful_scrapes += 1
            
            scraping_results.append({
                "scraping": result,
                "analysis": analysis_result
            })
        
        return jsonify({
            "scraping_results": scraping_results,
            "summary": {
                "total": len(urls),
                "successful_scrapes": successful_scrapes,
                "failed": len(urls) - successful_scrapes
            }
        })
        
    except Exception as e:
        app.logger.error(f"Bulk scraping error: {str(e)}")
        return jsonify({"error": f"Bulk scraping failed: {str(e)}"}), 500

@login_required
def simulate_scrape():
    """Simulate scraping with sample data or try real scraping"""
    try:
        # Try to scrape a sample URL
        sample_url = "https://httpbin.org/html"
        result = quick_scrape(sample_url)
        
        if result['success']:
            # Extract sensitive info
            nlp_results = extract_sensitive_info(result['content'])
            
            return jsonify({
                "source": result['content'][:1000] + "..." if len(result['content']) > 1000 else result['content'],
                "extracted": nlp_results,
                "scraped_count": 1,
                "is_real_data": True
            })
        else:
            # Fall back to sample data
            sample_data = sanitize_sample_data()
            sample_data["error"] = result.get('error', 'Scraping failed')
            return jsonify(sample_data)
            
    except Exception as e:
        app.logger.error(f"Scraping failed: {str(e)}")
        sample_data = sanitize_sample_data()
        sample_data["error"] = f"Scraping service unavailable: {str(e)}"
        return jsonify(sample_data)

@app.route("/api/hibp_breach", methods=["POST"])
@login_required
def hibp_breach():
    email = request.json.get('email')
    breaches = check_breach(email)
    return jsonify({"breaches": breaches})

@app.route("/api/abuseipdb", methods=["POST"])
@login_required
def abuseipdb():
    ip = request.json.get('ip')
    if not ip:
        return jsonify([{"error": "IP address is required"}]), 400
    abuse_info = check_abuse(ip)
    return jsonify(abuse_info)

@app.route("/api/virustotal", methods=["POST"])
@login_required
def virustotal():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    vt_data = check_domain_security(domain)
    return jsonify(vt_data)

@app.route("/api/quick_scan", methods=["POST"])
def quick_scan():
    try:
        data = request.get_json()
        text = data.get("text", "")
        if not text:
            return jsonify({"error": "No text provided"}), 400
        
        results = extract_sensitive_info(text)

        return jsonify({
            "emails": results["emails"],
            "ips": results["ips"],
            "passwords": results["passwords"],
            "api_keys": results["api_keys"]
        })
    except Exception as e:
        return jsonify({"error": f"Error scanning text: {str(e)}"}), 500

@app.route("/api/full_scan", methods=["POST"])
@login_required
def full_scan():
    data = request.get_json()
    email, ip_input, domain = data.get("email", ""), data.get("ip", ""), data.get("domain", "")
    results = {}
    ip_list = [ip.strip() for ip in ip_input.split(",")] if ip_input else []
    if ip_list:
        try:
            results["abuse"] = check_abuse(ip_list)
        except Exception as e:
            results["abuse"] = {"error": str(e)}
    if email:
        try:
            results["hibp"] = check_breach(email)
        except Exception as e:
            results["hibp"] = {"error": str(e)}
    if domain:
        try:
            results["virustotal"] = check_domain_security(domain)
        except Exception as e:
            results["virustotal"] = {"error": str(e)}
    try:
        risk_features = extract_risk_features(results)
        results['risk_score'] = predict_risk_score(**risk_features)
    except Exception as e:
        results['risk_score'] = "Unable to calculate risk score"
    return jsonify(results)

def extract_risk_features(results):
    hibp_count = len(results.get('hibp', [])) if isinstance(results.get('hibp'), list) else 0
    open_ports = extract_open_ports(results.get('shodan', []))
    abuse_score = calculate_abuse_score(results.get('abuse', []))
    services_exposed = estimate_exposed_services(results)
    nlp_leaks = estimate_nlp_leaks(results)
    return {'hibp_count': hibp_count, 'open_ports': open_ports, 'abuse_score': abuse_score, 'services_exposed': services_exposed, 'nlp_leaks': nlp_leaks}

def calculate_abuse_score(abuse_results):
    if not abuse_results or isinstance(abuse_results, dict):
        return 0
    scores = []
    for ip_data in abuse_results:
        if isinstance(ip_data, dict) and 'abuseConfidenceScore' in ip_data:
            scores.append(ip_data['abuseConfidenceScore'])
    return sum(scores) / len(scores) if scores else 0

def extract_open_ports(shodan_results):
    if not shodan_results:
        return 0
    ports = []
    for result in shodan_results:
        if isinstance(result, dict) and 'ports' in result and result['ports']:
            ports.extend(result['ports'])
    return len(set(ports))

def estimate_exposed_services(results):
    services = 0
    shodan_results = results.get('shodan', [])
    for result in shodan_results:
        if isinstance(result, dict) and 'ports' in result:
            services += len(result['ports'])
    return min(services, 10)

def estimate_nlp_leaks(results):
    leaks = 0
    hibp_breaches = results.get('hibp', [])
    if isinstance(hibp_breaches, list):
        leaks += len(hibp_breaches)
    if 'virustotal' in results and 'security_metrics' in results['virustotal']:
        vt_metrics = results['virustotal']['security_metrics']
        leaks += vt_metrics.get('malicious', 0) * 2
        leaks += vt_metrics.get('suspicious', 0)
    return min(leaks, 5)

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(429)
def rate_limit_error(error):
    return jsonify({"error": "Rate limit exceeded"}), 429

if __name__ == "__main__":
    app.run(debug=True)
