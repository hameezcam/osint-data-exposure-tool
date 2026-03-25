import requests
from bs4 import BeautifulSoup
import time
import re
from urllib.robotparser import RobotFileParser
from urllib.parse import urljoin, urlparse
import random

class WebScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        self.respect_robots = True
        self.delay_between_requests = 2  # seconds
        self.timeout = 10

    def can_scrape(self, url):
        """Check if we're allowed to scrape this URL"""
        if not self.respect_robots:
            return True
            
        try:
            parsed_url = urlparse(url)
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
            
            robot_parser = RobotFileParser()
            robot_parser.set_url(robots_url)
            try:
                robot_parser.read()
                return robot_parser.can_fetch("*", url)
            except:
                # If robots.txt can't be read, proceed with caution
                return True
        except Exception:
            return True

    def scrape_url(self, url, selectors=None, extract_text=True):
        """
        Scrape content from a single URL
        """
        try:
            # Check for known blocked domains
            blocked_domains = [
                'google.com', 'facebook.com', 'linkedin.com', 'twitter.com',
                'youtube.com', 'instagram.com', 'tiktok.com'
            ]
            
            parsed_url = urlparse(url)
            if any(domain in parsed_url.netloc for domain in blocked_domains):
                return {
                    "success": False,
                    "error": f"This website ({parsed_url.netloc}) has strong anti-bot protection and cannot be scraped with simple requests.",
                    "url": url,
                    "blocked": True
                }

            if not self.can_scrape(url):
                return {
                    "success": False,
                    "error": "Scraping disallowed by robots.txt",
                    "url": url
                }

            # Add random delay to be respectful
            time.sleep(self.delay_between_requests + random.uniform(0, 1))
            
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # Check if we got a valid HTML response
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type:
                return {
                    "success": False,
                    "error": f"URL returned non-HTML content: {content_type}",
                    "url": url
                }
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style", "nav", "header", "footer"]):
                script.decompose()
            
            scraped_data = {
                "success": True,
                "url": url,
                "title": "",
                "text_content": "",
                "selected_elements": [],
                "links_found": [],
                "metadata": {
                    "status_code": response.status_code,
                    "content_type": response.headers.get('content-type', ''),
                    "size_bytes": len(response.content)
                }
            }
            
            # Extract title
            title_tag = soup.find('title')
            if title_tag:
                scraped_data["title"] = title_tag.get_text().strip()
            
            # Extract text content
            if extract_text:
                # Get all text from body, or if no body, from the whole document
                body = soup.find('body')
                if body:
                    text_content = body.get_text(separator='\n', strip=True)
                else:
                    text_content = soup.get_text(separator='\n', strip=True)
                
                # Clean up excessive whitespace
                text_content = re.sub(r'\n\s*\n', '\n\n', text_content)
                text_content = re.sub(r'[ \t]+', ' ', text_content)
                scraped_data["text_content"] = text_content
            
            # Extract elements based on CSS selectors
            if selectors:
                for selector in selectors:
                    try:
                        elements = soup.select(selector)
                        for element in elements:
                            scraped_data["selected_elements"].append({
                                "selector": selector,
                                "text": element.get_text().strip(),
                                "html": str(element) if len(str(element)) < 500 else str(element)[:500] + "..."
                            })
                    except Exception as e:
                        continue  # Skip invalid selectors
            
            # Extract all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                try:
                    full_url = urljoin(url, href)
                    if full_url.startswith(('http://', 'https://')):
                        scraped_data["links_found"].append({
                            "text": link.get_text().strip()[:100],  # Limit text length
                            "url": full_url
                        })
                except:
                    continue
            
            return scraped_data
            
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Request timeout - website took too long to respond",
                "url": url
            }
        except requests.exceptions.TooManyRedirects:
            return {
                "success": False,
                "error": "Too many redirects",
                "url": url
            }
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"Request failed: {str(e)}",
                "url": url
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Scraping error: {str(e)}",
                "url": url
            }

def scrape_multiple_sources(urls, selectors=None):
    """
    Scrape multiple URLs with consistent formatting
    """
    scraper = WebScraper()
    results = []
    
    for url in urls:
        result = scraper.scrape_url(url, selectors)
        results.append(result)
        
        # Be respectful between requests
        time.sleep(scraper.delay_between_requests)
    
    return results

def extract_data_for_analysis(scraped_results):
    """
    Prepare scraped data for NLP analysis
    """
    combined_text = []
    
    for result in scraped_results:
        if result.get('success'):
            if result.get('text_content'):
                combined_text.append(result['text_content'])
            if result.get('selected_elements'):
                for element in result['selected_elements']:
                    combined_text.append(element['text'])
    
    return "\n".join(combined_text)

def quick_scrape(target_url):
    """
    Quick scrape function for immediate use in your app
    """
    scraper = WebScraper()
    result = scraper.scrape_url(target_url)
    
    if result['success']:
        return {
            "success": True,
            "content": result['text_content'],
            "title": result['title'],
            "url": result['url'],
            "metadata": result['metadata']
        }
    else:
        return {
            "success": False,
            "error": result['error'],
            "url": target_url,
            "blocked": result.get('blocked', False)
        }
