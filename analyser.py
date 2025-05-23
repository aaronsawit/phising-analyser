#!/usr/bin/env python3
"""
Phishing Link Analyzer - CLI Tool
A simple tool to analyze URLs for potential phishing indicators
"""

import sys
import re
import argparse
from urllib.parse import urlparse
import requests
from typing import List, Tuple, Dict

# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

class PhishingAnalyzer:
    def __init__(self):
        # Common brand domains for lookalike detection
        self.trusted_brands = [
            'microsoft', 'google', 'amazon', 'apple', 'facebook', 'paypal',
            'instagram', 'twitter', 'linkedin', 'netflix', 'spotify',
            'github', 'dropbox', 'adobe', 'yahoo', 'outlook'
        ]
        
        # Whitelist of trusted domains (these should never be flagged as malicious)
        self.trusted_domains = {
            'google.com', 'www.google.com', 'gmail.com', 'youtube.com',
            'microsoft.com', 'www.microsoft.com', 'outlook.com', 'office.com',
            'amazon.com', 'www.amazon.com', 'aws.amazon.com',
            'apple.com', 'www.apple.com', 'icloud.com',
            'facebook.com', 'www.facebook.com', 'instagram.com', 'whatsapp.com',
            'twitter.com', 'www.twitter.com', 'x.com',
            'linkedin.com', 'www.linkedin.com',
            'github.com', 'www.github.com',
            'paypal.com', 'www.paypal.com',
            'netflix.com', 'www.netflix.com',
            'spotify.com', 'www.spotify.com',
            'dropbox.com', 'www.dropbox.com',
            'adobe.com', 'www.adobe.com',
            'yahoo.com', 'www.yahoo.com',
            'cloudflare.com', 'www.cloudflare.com',
            'stackoverflow.com', 'www.stackoverflow.com'
        }
        
        # Common character substitutions used in phishing
        self.char_substitutions = {
            'o': ['0', 'ο', 'о'],  # Latin o, zero, Greek omicron, Cyrillic o
            'a': ['α', 'а'],       # Greek alpha, Cyrillic a
            'e': ['ε', 'е'],       # Greek epsilon, Cyrillic e
            'i': ['1', 'l', 'ι'],  # one, lowercase L, Greek iota
            'm': ['rn'],           # m can look like 'rn'
            'n': ['π'],            # Greek pi
        }
        
        # Mock blocklist - in real implementation, this would be fetched from APIs
        self.known_malicious_domains = {
            'phishing-example.com',
            'fake-bank-login.net',
            'malicious-site.org',
            'scam-portal.biz'
        }

    def validate_url(self, url: str) -> bool:
        """Validate if the input is a proper URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def extract_domain(self, url: str) -> str:
        """Extract domain name from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""

    def check_blocklist(self, domain: str) -> Tuple[bool, str]:
        """Check if domain is in known malicious blocklists"""
        # First check if domain is in trusted whitelist
        if domain in self.trusted_domains:
            return False, "✅ Domain is in trusted whitelist"
        
        # Check local mock blocklist
        if domain in self.known_malicious_domains:
            return True, "Found in local blocklist"
        
        # Check OpenPhish feed (completely free, no API key needed)
        try:
            print(f"   🔍 Checking OpenPhish feed...")
            response = requests.get("https://openphish.com/feed.txt", timeout=10)
            if response.status_code == 200:
                # OpenPhish contains full URLs, check for exact domain matches
                feed_content = response.text.lower()
                feed_lines = feed_content.split('\n')
                
                for line in feed_lines:
                    if line.strip():  # Skip empty lines
                        try:
                            # Extract domain from URL in feed
                            parsed_url = urlparse(line.strip())
                            feed_domain = parsed_url.netloc.lower()
                            
                            # Check for exact match or subdomain match
                            if feed_domain == domain or feed_domain.endswith('.' + domain):
                                return True, "🚨 Found in OpenPhish feed"
                        except:
                            continue
            else:
                print(f"   ⚠️ OpenPhish API returned status {response.status_code}")
        except requests.RequestException as e:
            print(f"   ⚠️ Could not reach OpenPhish: {str(e)[:50]}...")
        
        # Check URLhaus (also free) - improved parsing
        try:
            print(f"   🔍 Checking URLhaus...")
            response = requests.post("https://urlhaus-api.abuse.ch/v1/host/", 
                                   data={"host": domain}, timeout=10)
            if response.status_code == 200:
                result = response.json()
                # URLhaus returns "ok" if domain is found as malicious
                # "no_results" if domain is clean/not found
                if result.get("query_status") == "ok" and result.get("urls"):
                    # Double-check it's actually our domain, not just containing it
                    for url_entry in result.get("urls", []):
                        url_host = url_entry.get("url_host", "").lower()
                        if url_host == domain:
                            return True, "🚨 Found in URLhaus feed"
        except requests.RequestException as e:
            print(f"   ⚠️ Could not reach URLhaus: {str(e)[:50]}...")
        except Exception:
            pass
        
        return False, "✅ Not found in threat feeds"

    def detect_lookalikes(self, domain: str) -> Tuple[bool, str]:
        """Detect if domain resembles known brands using common tricks"""
        domain_clean = domain.replace('www.', '').split('.')[0]
        
        for brand in self.trusted_brands:
            # Check for exact substring match
            if brand in domain_clean and domain_clean != brand:
                return True, f"Contains '{brand}' brand name"
            
            # Check for character substitution attacks
            if self._check_character_substitution(domain_clean, brand):
                return True, f"Resembles '{brand}' with character substitution"
            
            # Check for homograph attacks (similar looking characters)
            if self._check_homograph_attack(domain_clean, brand):
                return True, f"Potential homograph attack on '{brand}'"
        
        return False, "No brand impersonation detected"

    def _check_character_substitution(self, domain: str, brand: str) -> bool:
        """Check for common character substitution patterns"""
        # Simple implementation - check if domain is similar to brand with substitutions
        if len(domain) != len(brand):
            return False
        
        differences = 0
        for i, (d_char, b_char) in enumerate(zip(domain, brand)):
            if d_char != b_char:
                # Check if it's a common substitution
                if b_char in self.char_substitutions:
                    if d_char in self.char_substitutions[b_char]:
                        differences += 1
                    else:
                        return False
                else:
                    return False
        
        return 1 <= differences <= 2  # Allow 1-2 character substitutions

    def _check_homograph_attack(self, domain: str, brand: str) -> bool:
        """Basic homograph attack detection"""
        # Check for mixed scripts or suspicious Unicode characters
        try:
            domain.encode('ascii')
            return False  # Pure ASCII, no homograph attack
        except UnicodeEncodeError:
            # Contains non-ASCII characters - potential homograph
            return True

    def check_suspicious_patterns(self, domain: str) -> List[str]:
        """Check for other suspicious patterns in the domain"""
        warnings = []
        
        # Check for excessive subdomains
        if domain.count('.') > 3:
            warnings.append("Excessive subdomains")
        
        # Check for suspicious keywords
        suspicious_keywords = ['login', 'secure', 'verify', 'update', 'confirm']
        for keyword in suspicious_keywords:
            if keyword in domain:
                warnings.append(f"Contains suspicious keyword: '{keyword}'")
        
        # Check for URL shorteners (could hide real destination)
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        for shortener in shorteners:
            if shortener in domain:
                warnings.append("URL shortener detected")
        
        # Check for IP addresses instead of domain names
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, domain):
            warnings.append("IP address instead of domain name")
        
        return warnings

    def analyze_url(self, url: str) -> Dict:
        """Main analysis function"""
        results = {
            'url': url,
            'domain': '',
            'is_malicious': False,
            'is_suspicious': False,
            'blocklist_hit': False,
            'lookalike_detected': False,
            'warnings': [],
            'verdict': 'Unknown',
            'details': []
        }
        
        # Extract domain
        domain = self.extract_domain(url)
        results['domain'] = domain
        
        if not domain:
            results['verdict'] = 'Invalid'
            results['details'].append("Could not extract domain from URL")
            return results
        
        # Check blocklist
        is_blocked, block_msg = self.check_blocklist(domain)
        results['blocklist_hit'] = is_blocked
        results['details'].append(block_msg)
        
        # Check for lookalikes
        is_lookalike, lookalike_msg = self.detect_lookalikes(domain)
        results['lookalike_detected'] = is_lookalike
        results['details'].append(lookalike_msg)
        
        # Check other suspicious patterns
        warnings = self.check_suspicious_patterns(domain)
        results['warnings'] = warnings
        
        # Determine verdict
        if is_blocked:
            results['is_malicious'] = True
            results['verdict'] = 'Malicious'
        elif is_lookalike or warnings:
            results['is_suspicious'] = True
            results['verdict'] = 'Suspicious'
        else:
            results['verdict'] = 'Clean'
        
        return results

def print_results(results: Dict):
    """Print analysis results with color coding"""
    print(f"\n{Colors.BLUE}🔍 Analyzing:{Colors.END} {results['url']}")
    print(f"{Colors.BLUE}🌐 Domain:{Colors.END} {results['domain']}")
    
    # Print main findings
    for detail in results['details']:
        if "Found in" in detail:
            print(f"{Colors.RED}❌ {detail}{Colors.END}")
        elif "Not found" in detail:
            print(f"{Colors.GREEN}✅ {detail}{Colors.END}")
        elif "Resembles" in detail or "Contains" in detail:
            print(f"{Colors.YELLOW}🚨 {detail}{Colors.END}")
        else:
            print(f"ℹ️  {detail}")
    
    # Print warnings
    if results['warnings']:
        print(f"\n{Colors.YELLOW}⚠️  Additional warnings:{Colors.END}")
        for warning in results['warnings']:
            print(f"   • {warning}")
    
    # Print verdict
    verdict = results['verdict']
    if verdict == 'Malicious':
        color = Colors.RED
        emoji = "🔴"
    elif verdict == 'Suspicious':
        color = Colors.YELLOW
        emoji = "🟡"
    elif verdict == 'Clean':
        color = Colors.GREEN
        emoji = "🟢"
    else:
        color = Colors.BLUE
        emoji = "🔵"
    
    print(f"\n{color}{Colors.BOLD}{emoji} Verdict: {verdict}{Colors.END}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Phishing Link Analyzer - Check URLs for potential phishing indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishing_checker.py https://example.com
  python phishing_checker.py https://login-micros0ft.com
  python phishing_checker.py --url https://suspicious-site.com
        """
    )
    
    parser.add_argument(
        'url',
        nargs='?',
        help='URL to analyze'
    )
    
    parser.add_argument(
        '--url',
        dest='url_flag',
        help='URL to analyze (alternative method)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Phishing Analyzer v1.0'
    )
    
    args = parser.parse_args()
    
    # Get URL from either positional argument or flag
    url = args.url or args.url_flag
    
    if not url:
        print(f"{Colors.RED}Error: Please provide a URL to analyze{Colors.END}")
        print("Usage: python phishing_checker.py <URL>")
        print("Example: python phishing_checker.py https://example.com")
        sys.exit(1)
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Validate URL format
    analyzer = PhishingAnalyzer()
    if not analyzer.validate_url(url):
        print(f"{Colors.RED}Error: Invalid URL format{Colors.END}")
        sys.exit(1)
    
    try:
        # Analyze the URL
        results = analyzer.analyze_url(url)
        print_results(results)
        
        # Exit with appropriate code
        if results['verdict'] == 'Malicious':
            sys.exit(2)  # Malicious
        elif results['verdict'] == 'Suspicious':
            sys.exit(1)  # Suspicious
        else:
            sys.exit(0)  # Clean or Unknown
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Analysis interrupted by user{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}Error during analysis: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()