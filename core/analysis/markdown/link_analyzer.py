import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlunparse

class MockDomainReputationService:
    def check(self, domain: str) -> str:
        # Mocked: In real use, query a reputation API
        if domain.endswith(".ru") or domain in {"malicious.com", "phish.site"}:
            return "bad"
        return "good"

class MockRedirectChainAnalyzer:
    def analyze(self, url: str) -> List[str]:
        # Mocked: In real use, follow HTTP redirects
        if "redirect" in url:
            return [url, "https://final.destination.com"]
        return [url]

class MarkdownLinkAnalyzer:
    """
    Analyzes links in markdown for security issues.
    """

    # Regex to find URLs in typical markdown link format: [text](url) or <url>
    # It also captures plain URLs.
    URL_REGEX = re.compile(
        r'(?:\[[^\]]*\]\((?P<markdown_link>[^\s\)]+)\))'  # Catches [text](url)
        r'|(?:\<(?P<angle_link>[^\s>]+)\>)'  # Catches <url>
        r'|(?P<plain_link>https?://[^\s\'\"\]\)\<]+)',  # Catches http(s)://... plain links
        re.IGNORECASE
    )

    def __init__(
        self,
        reputation_service: Optional[MockDomainReputationService] = None,
        redirect_analyzer: Optional[MockRedirectChainAnalyzer] = None,
    ):
        self.reputation_service = reputation_service or MockDomainReputationService()
        self.redirect_analyzer = redirect_analyzer or MockRedirectChainAnalyzer()

    def analyze(self, markdown: str) -> Dict[str, Any]:
        extracted_urls = self.extract_urls(markdown)
        # Remove duplicates while preserving order
        unique_urls = sorted(list(set(extracted_urls)), key=extracted_urls.index)

        normalized_urls = []
        domain_reputations = {}
        redirect_chains_map = {}
        obfuscated_url_list = []

        for url in unique_urls:
            try:
                # Normalize first to avoid issues with malformed URLs in subsequent steps
                norm_url = self.normalize_url(url)
                normalized_urls.append(norm_url)

                parsed_url = urlparse(norm_url)
                domain = parsed_url.netloc
                if domain: # Ensure domain exists before checking reputation
                    domain_reputations[norm_url] = self.reputation_service.check(domain)
                
                redirect_chains_map[norm_url] = self.redirect_analyzer.analyze(norm_url)
                
                if self.is_obfuscated(url): # Check original URL for obfuscation
                    obfuscated_url_list.append(url)
            except ValueError: # Catch errors from urlparse on malformed URLs
                # Potentially log this malformed URL or handle as an issue
                obfuscated_url_list.append(url) # Treat malformed URLs as potentially obfuscated/problematic
                if url not in normalized_urls: # Add original if not already processed
                    normalized_urls.append(url) # Keep original if it can't be normalized
                # Assign default/error values for reputation and redirects for malformed URLs
                domain_reputations[url] = "error_parsing_url"
                redirect_chains_map[url] = [url, "error_parsing_url"]


        return {
            "urls": unique_urls,
            "normalized_urls": normalized_urls,
            "domain_reputation": domain_reputations,
            "redirect_chains": redirect_chains_map,
            "obfuscated_urls": obfuscated_url_list,
        }

    def extract_urls(self, markdown: str) -> List[str]:
        found_urls = []
        for match in self.URL_REGEX.finditer(markdown):
            if match.group("markdown_link"):
                found_urls.append(match.group("markdown_link"))
            elif match.group("angle_link"):
                found_urls.append(match.group("angle_link"))
            elif match.group("plain_link"):
                found_urls.append(match.group("plain_link"))
        
        # A simpler, broader regex for http/https might catch some missed by the above
        # This helps catch URLs not perfectly fitting markdown structures but still present.
        # Ensure it doesn't pick up parts of already found URLs or garbage.
        # Example: http://example.com without markdown []() or <>
        # The initial regex is quite good, but this can be a fallback.
        # Let's refine the primary regex to be more comprehensive.
        # The current URL_REGEX is designed to capture these cases.

        # Remove duplicates that might arise from overlapping regex patterns if we had multiple.
        # With the current combined regex, finditer should handle distinct matches.
        return list(dict.fromkeys(found_urls)) # Efficient way to get unique while preserving order

    def normalize_url(self, url: str) -> str:
        # Remove fragments, normalize scheme and netloc
        parsed = urlparse(url)
        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            '', '', ''  # Remove params, query, fragment
        ))

    def is_obfuscated(self, url: str) -> bool:
        # Detect various obfuscation techniques
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme.lower()
        hostname = parsed_url.hostname if parsed_url.hostname else "" # Ensure hostname is a string

        # Check for non-http(s) schemes that can be risky in markdown
        if scheme not in ['http', 'https', 'ftp', 'mailto', '']: # allow empty for relative paths
            if scheme in ['javascript', 'data', 'vbscript']:
                return True

        # URL-encoded characters (beyond typical query string usage)
        # Check path and hostname for excessive encoding
        path_plus_hostname = parsed_url.path + hostname
        if len(re.findall(r'%[0-9a-fA-F]{2}', path_plus_hostname)) > 5: # Arbitrary threshold for "excessive"
            return True
        
        # Unicode escapes in hostname or path
        if re.search(r'\\u[0-9a-fA-F]{4}', url):
            return True

        # IP Address as Decimal or other non-standard IP formats
        # Normal IP: 1.2.3.4 - urlparse.hostname handles this well
        # Decimal IP: http://1234567890 - urlparse.hostname might be just the number string
        if re.match(r'^\d+$', hostname) and '.' not in hostname: # Looks like a decimal IP
             # Check if it's a common port number or a very large number (likely decimal IP)
            try:
                if int(hostname) > 65535: # Ports are <= 65535. Larger numbers are likely decimal IPs.
                    return True
            except ValueError:
                pass # Not a simple integer

        # Userinfo in URL (e.g., http://user:pass@example.com)
        if parsed_url.username or parsed_url.password:
            # A more specific check for common obfuscation trick with @
            if "@" in parsed_url.netloc and parsed_url.netloc.count('@') > 0:
                 # if the part after the last @ is different from hostname, it's likely an attempt to hide the real domain
                real_host_candidate = parsed_url.netloc.split('@')[-1]
                if urlparse(f"http://{real_host_candidate}").hostname != hostname:
                    return True


        # Excessive dots in hostname (potential subdomain enumeration or obfuscation)
        if hostname.count('.') > 7:  # Arbitrary threshold
            return True

        # Punycode (IDN homograph attacks)
        if "xn--" in hostname:
            return True
            
        # Keywords in URL that might indicate obfuscation attempts or strange structures
        # This is a bit heuristic and might need refinement
        obfuscation_keywords = ["@", ".exe", ".bat", ".sh", ".js"] # some are more about payload than obfuscation
        for kw in obfuscation_keywords:
            if kw in url.lower(): # check original url for these
                # More specific check for @ in path, not just netloc
                if kw == "@" and "@" in parsed_url.path: # e.g. /path/to/file@lookslikedomain.com
                    return True
                elif kw != "@": # For other keywords
                    return True


        # Bracket/Parenthesis/Curly Brace obfuscation (already present, kept for clarity)
        # This typically applies to the whole URL string, not just parsed components
        if re.search(r'[\[\]\(\)\{\}]', url): # Check the raw url
             # Check if these are part of query parameters or path, which can be legitimate
             # but if they are in the scheme or netloc, it's suspicious
            if re.search(r'[\[\]\(\)\{\}]', scheme + "://" + parsed_url.netloc):
                 return True
        
        # Very long URLs
        if len(url) > 2000: # Common URL length limit
            return True

        return False