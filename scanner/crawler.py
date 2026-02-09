import requests
from bs4 import BeautifulSoup
from scanner.utils import normalize_url, is_same_domain
from scanner.config import USER_AGENT, TIMEOUT, MAX_DEPTH

class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited = set()
        self.endpoints = set()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def crawl(self, url=None, depth=0):
        if depth > MAX_DEPTH:
            return

        if url is None:
            url = self.base_url

        if url in self.visited:
            return

        self.visited.add(url)

        try:
            response = self.session.get(url, timeout=TIMEOUT)
            response.raise_for_status()  # Raise exception for HTTP errors
        except (requests.RequestException, requests.HTTPError) as e:
            print(f"Error crawling {url}: {e}")
            return

        # Check if content is HTML before parsing
        content_type = response.headers.get('content-type', '')
        if 'text/html' not in content_type:
            self.endpoints.add(url)  # Add non-HTML URLs as endpoints
            return

        self.endpoints.add(url)

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            
            for link in soup.find_all("a", href=True):
                full_url = normalize_url(url, link["href"])
                
                # Prevent infinite recursion with circular references
                if (is_same_domain(self.base_url, full_url) and
                    full_url not in self.visited and
                    full_url != url):  # Avoid self-reference
                    
                    self.crawl(full_url, depth + 1)
                    
        except Exception as e:
            print(f"Error parsing HTML from {url}: {e}")

    def get_endpoints(self):
        return list(self.endpoints)
