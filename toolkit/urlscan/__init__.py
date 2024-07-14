import os
import asyncio
import nest_asyncio
from .urlscan import UrlScan

nest_asyncio.apply()

api_key = os.getenv('URLSCAN_API_KEY')

if api_key:
    _urlscan = UrlScan(api_key=api_key)
else:
    _urlscan = None


def get_result_data(scan_uuid, show=True):
    if _urlscan:
        result = asyncio.run(_urlscan.get_result_data(scan_uuid))
        show and print(result)
        return result
    else:
        raise ValueError("API key not set. Please set the URLSCAN_API_KEY environment variable.")


def investigate(url, private=False, show=True):
    if _urlscan:
        result = asyncio.run(_urlscan.investigate(url, private))
        show and print(result)
        return result
    else:
        raise ValueError("API key not set. Please set the URLSCAN_API_KEY environment variable.")


def search(query, show=True):
    if _urlscan:
        result = asyncio.run(_urlscan.search(query))
        show and print(result)
        return result
    else:
        raise ValueError("API key not set. Please set the URLSCAN_API_KEY environment variable.")
