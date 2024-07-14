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

import asyncio
import os

from .client import *
from .error import *
from .feed import *
from .iterator import *
from .object import *
from .version import __version__

api_key = os.getenv('VIRUSTOTAL_API_KEY')

if api_key:
    _vt_client = Client(apikey=api_key)
else:
    _vt_client = None


def scan_url(url, wait_for_completion=False, show=True):
    if _vt_client:
        result = asyncio.run(_vt_client.scan_url_async(url, wait_for_completion))
        show and print(result)
        return result
    else:
        raise ValueError("API key not set. Please set the VIRUSTOTAL_API_KEY environment variable.")


def get_url_analysis(url, show=True):
    if _vt_client:
        url_id = client.url_id(url)
        url_analysis = _vt_client.get_object("/urls/{}", url_id)
        show and print(url_analysis)
        return url_analysis
    else:
        raise ValueError("API key not set. Please set the VIRUSTOTAL_API_KEY environment variable.")


def scan_file(file_path, wait_for_completion=False, show=True):
    if _vt_client:
        with open(file_path, "rb") as f:
            result = asyncio.run(_vt_client.scan_file_async(f, wait_for_completion))
            show and print(result)
            return result
    else:
        raise ValueError("API key not set. Please set the VIRUSTOTAL_API_KEY environment variable.")


def get_file_analysis(file_hash, show=True):
    if _vt_client:
        file_analysis = _vt_client.get_object("/files/{}", file_hash)
        if show:
            print(f"Size: {file_analysis.size}")
            print(f"SHA-256: {file_analysis.sha256}")
            print(f"Type: {file_analysis.type_tag}")
            print(f"Last Analysis Stats: {file_analysis.last_analysis_stats}")
        return file_analysis
    else:
        raise ValueError("API key not set. Please set the VIRUSTOTAL_API_KEY environment variable.")
