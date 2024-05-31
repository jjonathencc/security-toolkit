import os
import asyncio
import nest_asyncio
from .urlscan import UrlScan

# Apply the nest_asyncio patch
nest_asyncio.apply()

# Get API key from environment variable or set it to None
api_key = os.getenv('URLSCAN_API_KEY')

# Create a single instance of UrlScan to use within this module
if api_key:
    _urlscanner = UrlScan(api_key=api_key)
else:
    _urlscanner = None


def investigate(url, private=False):
    """Submits a URL scan request and prints the results."""
    if _urlscanner:
        result = asyncio.run(_urlscanner.investigate(url, private))
        print(result)
    else:
        raise ValueError("API key not set. Please set the URLSCAN_API_KEY environment variable.")


def search(query):
    """Searches the URL scan database and prints the results."""
    if _urlscanner:
        result = asyncio.run(_urlscanner.search(query))
        print(result)
    else:
        raise ValueError("API key not set. Please set the URLSCAN_API_KEY environment variable.")
