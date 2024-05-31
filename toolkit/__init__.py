from .urlscan import investigate as urlscan_investigate, search as urlscan_search
from .virustotal import scan_url as virustotal_scan_url, get_url_analysis as virustotal_get_url_analysis


def double_scan(url):
    """Performs a double scan using URLScan and VirusTotal and prints the results."""
    print("URLScan Result:")
    urlscan_investigate(url)
    print("\nVirusTotal Result:")
    virustotal_get_url_analysis(url)


__all__ = ['urlscan', 'virustotal', 'double_scan']
