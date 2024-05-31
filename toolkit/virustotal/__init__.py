#!/usr/local/bin/python
# Copyright © 2019 The vt-py authors. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""VT module."""

from .client import *
from .error import *
from .feed import *
from .iterator import *
from .object import *
from .version import __version__

import os
import asyncio

# Get API key from environment variable or set it to None
api_key = os.getenv('VIRUSTOTAL_API_KEY')

# Create a single instance of Client to use within this module
if api_key:
    _vt_client = Client(apikey=api_key)
else:
    _vt_client = None


def scan_url(url, wait_for_completion=False):
    """Scans a URL using the VirusTotal API and prints the results."""
    if _vt_client:
        result = asyncio.run(_vt_client.scan_url_async(url, wait_for_completion))
        print(result)
    else:
        raise ValueError("API key not set. Please set the VIRUSTOTAL_API_KEY environment variable.")


def get_url_analysis(url):
    """Fetches and prints detailed analysis for a URL from VirusTotal."""
    if _vt_client:
        url_id = client.url_id(url)
        url_analysis = _vt_client.get_object("/urls/{}", url_id)
        print(f"Times Submitted: {url_analysis.times_submitted}")
        print(f"Last Analysis Stats: {url_analysis.last_analysis_stats}")
    else:
        raise ValueError("API key not set. Please set the VIRUSTOTAL_API_KEY environment variable.")
