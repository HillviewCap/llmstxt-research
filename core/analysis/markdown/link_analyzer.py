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

    URL_REGEX = re.compile(
        r'(https?://[^\s\]\)]+)', re.IGNORECASE
    )

    def __init__(
        self,
        reputation_service: Optional[MockDomainReputationService] = None,
        redirect_analyzer: Optional[MockRedirectChainAnalyzer] = None,
    ):
        self.reputation_service = reputation_service or MockDomainReputationService()
        self.redirect_analyzer = redirect_analyzer or MockRedirectChainAnalyzer()

    def analyze(self, markdown: str) -> Dict[str, Any]:
        urls = self.extract_urls(markdown)
        normalized = [self.normalize_url(u) for u in urls]
        reputation = {u: self.reputation_service.check(urlparse(u).netloc) for u in normalized}
        redirects = {u: self.redirect_analyzer.analyze(u) for u in normalized}
        obfuscated = [u for u in urls if self.is_obfuscated(u)]
        return {
            "urls": urls,
            "normalized_urls": normalized,
            "domain_reputation": reputation,
            "redirect_chains": redirects,
            "obfuscated_urls": obfuscated,
        }

    def extract_urls(self, markdown: str) -> List[str]:
        return self.URL_REGEX.findall(markdown)

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
        # Detect basic obfuscation: hex, unicode, or IP-as-decimal
        if re.search(r'%[0-9a-fA-F]{2}', url):
            return True  # URL-encoded
        if re.search(r'\\u[0-9a-fA-F]{4}', url):
            return True  # Unicode escapes
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            return False  # Normal IP
        if re.match(r'https?://\d+', url):
            return True  # Decimal IP
        if re.search(r'[\[\]\(\)\{\}]', url):
            return True  # Bracket obfuscation
        return False