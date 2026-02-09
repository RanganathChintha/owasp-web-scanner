from urllib.parse import urljoin, urlparse

def is_same_domain(base_url, target_url):
    return urlparse(base_url).netloc == urlparse(target_url).netloc

def normalize_url(base, link):
    return urljoin(base, link)
