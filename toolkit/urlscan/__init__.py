import asyncio
import json
import os
from pathlib import Path

import click
import nest_asyncio

from .urlscan import UrlScan
from ..utilities.exception import APIError

nest_asyncio.apply()

api_key = os.getenv('URLSCAN_API_KEY')

if api_key:
    api = UrlScan(api_key=api_key)
else:
    api = None


def investigate_url(url, private=False, standalone=True):
    """Investigate a URL."""
    try:
        result = asyncio.run(api.investigate(url, private))
        if not result:
            click.secho("Investigation failed. Please try again later.", fg='red')
        else:
            if result.keys() >= {"report", "screenshot", "dom"} and standalone:
                click.secho(f"{'Scan report URL':<31}", fg='cyan', nl=False)
                click.secho(result['report'], fg='green')
                click.secho(f"{'Screenshot download location':<31}", fg='cyan', nl=False)
                click.secho(result['screenshot'], fg='green')
                click.secho(f"{'DOM download location':<31}", fg='cyan', nl=False)
                click.secho(result['dom'], fg='green')
            else:
                return result['scan_uuid']
    except APIError as e:
        raise click.ClickException(e.value)


def retrieve_result(uuid):
    """Retrieve the result of a scan."""
    try:
        result = asyncio.run(api.fetch_result(uuid))
        click.secho(f"{'Scan report URL':<31}", fg='cyan', nl=False)
        click.secho(result['report'], fg='green')
        click.secho(f"{'Screenshot download location':<31}", fg='cyan', nl=False)
        click.secho(result['screenshot'], fg='green')
        click.secho(f"{'DOM download location':<31}", fg='cyan', nl=False)
        click.secho(result['dom'], fg='green')
    except APIError as e:
        raise click.ClickException(e.value)


def submit_scan_request(url, private=False, standalone=True):
    """Submit a URL scan request."""
    try:
        scan_uuid = asyncio.run(api.submit_scan_request(url, private))
        if not scan_uuid:
            click.secho(f"Failed to submit scan request for {url}. Please try again later.", fg='red')
        else:
            if standalone:
                click.secho(f"{'Scan UUID':<31}", fg='cyan', nl=False)
                click.secho(scan_uuid, fg='green')
            else:
                return scan_uuid
    except APIError as e:
        raise click.ClickException(e.value)


def batch_investigate(file_path, private=False):
    """Batch investigate URLs from a file."""
    try:
        asyncio.run(api.batch_investigate(file_path, private))
        click.secho(f"Investigation outputs written to {Path(file_path).stem}.csv", fg='green')
    except APIError as e:
        raise click.ClickException(e.value)


def search_query(query):
    """Search URLs based on a query."""
    try:
        results = asyncio.run(api.search(query))
        if results:
            click.secho(json.dumps(results, indent=1, default=str), fg='green')
    except APIError as e:
        raise click.ClickException(e.value)


def get_report_data(uuid, standalone=True):
    """Get report data for a URL scan."""
    try:
        results = asyncio.run(api.get_result_data(uuid))
        if results and standalone:
            print_report(results)
        elif results:
            return results
    except APIError as e:
        raise click.ClickException(e.value)


def print_report(data, limit=3):
    def truncate(value, length=600):
        return (str(value)[:length] + '...') if len(str(value)) > length else str(value)

    def print_dict_items(items, indent_level=0):
        indent = '  ' * indent_level
        for sub_key, sub_value in items.items():
            if isinstance(sub_value, list) and all(isinstance(i, dict) for i in sub_value):
                click.secho(f"{indent}{sub_key}", fg='white')
                for idx, item in enumerate(sub_value[:limit], start=1):
                    click.secho(f"{indent}  item {idx}", fg='white')
                    print_dict_items(item, indent_level + 2)
            else:
                sub_value_str = truncate(sub_value)
                click.secho(f"{indent}{sub_key:<30}", fg='white', nl=False)
                click.secho(sub_value_str, fg='green')

    if not data:
        click.echo("No data to display")
        return

    if not isinstance(data, dict):
        click.echo(f"Unexpected data type: {type(data)}")
        return

    click.secho('Report Data:', fg='yellow')
    for key, value in data.items():
        if key in ["data", "stats"]:
            continue
        click.echo('')
        click.echo(f"{key.capitalize()}:", )
        if isinstance(value, list):
            if all(isinstance(i, dict) for i in value):
                for idx, item in enumerate(value[:limit], start=1):
                    click.secho(f"  item {idx}:", fg='cyan')
                    print_dict_items(item, 2)
            else:
                for item in value[:limit]:
                    click.secho(f"  {truncate(item)}", fg='green')
        elif isinstance(value, dict):
            print_dict_items(value, 1)
        else:
            value_str = truncate(value)
            click.secho(f"  {value_str}", fg='green')
