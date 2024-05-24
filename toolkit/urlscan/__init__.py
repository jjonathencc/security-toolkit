import os
import asyncio
from .urlscan import UrlScan

# Get API key from environment variable or set it to None
api_key = os.getenv('URLSCAN_API_KEY')

# Create a single instance of UrlScan to use within this module
if api_key:
    urlscan_instance = UrlScan(api_key=api_key)
else:
    urlscan_instance = None


def scan_url(url, private=False):
    """Submits a URL scan request and returns the results."""
    if urlscan_instance:
        return asyncio.run(urlscan_instance.investigate(url, private))
    else:
        raise ValueError("API key not set. Please set the URLSCAN_API_KEY environment variable.")


def search(query):
    """Searches the URL scan database with the given query."""
    if urlscan_instance:
        return asyncio.run(urlscan_instance.search(query))
    else:
        raise ValueError("API key not set. Please set the URLSCAN_API_KEY environment variable.")
