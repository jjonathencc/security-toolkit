from .urlscan import urlscan

_url_scanner = UrlScan()


def urlscan(url):
    """Scan a URL using the urlscan.io service."""
    return _url_scanner.scan_url(url)
