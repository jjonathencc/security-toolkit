import toolkit.urlscan as urlscan
import toolkit.virustotal as virustotal


def double_scan(url):
    """Performs a double scan using URLScan and VirusTotal."""
    urlscan_result = urlscan.investigate(url)
    virustotal_result = virustotal.scan_url(url)
    return {'urlscan': urlscan_result, 'virustotal': virustotal_result}


def main():
    # Example usage of combined functionality
    url = 'https://example.com'
    result = double_scan(url)
    print(result)
