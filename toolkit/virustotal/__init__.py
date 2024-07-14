"""VT module."""

import os
from contextlib import contextmanager

import click
import validators

from toolkit.utilities.exception import APIError
from toolkit.virustotal.client import *
from toolkit.virustotal.object import *

api_key = os.getenv('VIRUSTOTAL_API_KEY')

if api_key:
    api = Client(apikey=api_key)
else:
    api = None


@contextmanager
def get_api():
    if api is None:
        raise click.ClickException("API key not set. Please set the VIRUSTOTAL_API_KEY environment variable.")
    try:
        yield api
    finally:
        api.close()


def url_id(url):
    return client.url_id(url)


def get_object(path, *path_args, params=None):
    if validators.url(path):
        path = '/urls/' + url_id(path)
    try:
        with get_api() as api:
            obj = api.get_object(path, *path_args, params)
            print_object(obj)
    except APIError as e:
        raise click.ClickException(e.value)


def file_scan(path, wait_for_completion=True):
    try:
        with get_api() as api:
            with open(path, "rb") as f:
                click.secho('Scanning file, please wait...', fg='yellow')
                click.echo('')
                analysis = api.scan_file(f, wait_for_completion)
            print_object(analysis)
    except APIError as e:
        raise click.ClickException(e.value)


def url_scan(url, wait_for_completion=True):
    try:
        with get_api() as api:
            click.secho('Scanning URL, please wait...', fg='yellow')
            click.echo('')
            analysis = api.scan_url(url, wait_for_completion)
            print_object(analysis)
    except APIError as e:
        raise click.ClickException(e.value)


def file_download(file_hash, path):
    try:
        with get_api() as api:
            with open(path, "wb") as f:
                click.secho('Downloading file, please wait...', fg='yellow')
                api.download_file(file_hash, f)
            click.secho(f'File successfully downloaded to {path}', fg='green')
    except APIError as e:
        raise click.ClickException(e.value)


def retrohunt_job(job_id):
    try:
        with get_api() as api:
            job = api.get_object(f"/intelligence/retrohunt_jobs/{job_id}")
            click.echo('Retrohunt Job Details:')
            click.secho(f"{'Job ID':<30}", fg='cyan', nl=False)
            click.secho(job.id, fg='green')
            click.secho(f"{'Status':<30}", fg='cyan', nl=False)
            click.secho(job.status, fg='green')
            click.secho(f"{'Progress':<30}", fg='cyan', nl=False)
            click.secho(f"{job.progress}%", fg='green')
    except APIError as e:
        raise click.ClickException(e.value)


def start_retrohunt_job(rules):
    try:
        with get_api() as api:
            job = api.Object("retrohunt_job")
            job.rules = rules
            job = api.post_object("/intelligence/retrohunt_jobs", obj=job)
            click.secho('Retrohunt job started with ID:', nl=False)
            click.secho(job.id, fg='cyan')
    except APIError as e:
        raise click.ClickException(e.value)


def abort_retrohunt_job(job_id):
    try:
        with get_api() as api:
            api.post(f"/intelligence/retrohunt_jobs/{job_id}/abort")
            click.secho('Retrohunt job ', nl=False)
            click.secho(job_id, fg='cyan', nl=False)
            click.secho(' aborted successfully.')
    except APIError as e:
        raise click.ClickException(e.value)


def create_livehunt_ruleset(name, rules):
    try:
        with get_api() as api:
            ruleset = api.Object("hunting_ruleset")
            ruleset.name = name
            ruleset.rules = rules
            ruleset = api.post_object("/intelligence/hunting_rulesets", obj=ruleset)
            click.secho('LiveHunt ruleset created with ID:', nl=False)
            click.secho(ruleset.id, fg='cyan')
            return ruleset
    except APIError as e:
        raise click.ClickException(e.value)


def print_object(obj, full=False, limit=5):
    if not obj:
        click.echo("No data to display")
        return
    if isinstance(obj, object.Object):
        data = obj.to_dict()
    elif isinstance(obj, dict):
        data = obj
    else:
        click.echo(f"Unexpected object type: {type(obj)}")
        return
    attributes = data.get("attributes", {})
    links = data.get('links', {})
    click.echo('Object Information:')
    click.secho(f"{'Object ID':<40}", fg='cyan', nl=False)
    click.secho(f"{data.get('id', 'N/A')}", fg='green')
    if links:
        click.secho(f"{'Object Link':<40}", fg='cyan', nl=False)
        click.secho(f"{links.get('self', 'N/A')}", fg='green')
    click.secho(f"{'Object Type':<40}", fg='cyan', nl=False)
    click.secho(f"{data.get('type', 'N/A')}", fg='green')
    click.echo('')
    click.echo("Attributes:")
    for key, value in attributes.items():
        formatted_key = key.replace('_', ' ').capitalize()
        if full is False and key in ("last_http_response_headers", "trackers", "results"):
            continue
        elif key in ("last_analysis_results", "categories", "trackers", "html_meta", "last_analysis_stats"):
            click.secho(f"{formatted_key}", fg='cyan')
            limited_results = dict(list(value.items())[:limit])
            for sub_key, sub_value in limited_results.items():
                click.secho(f"  {sub_key:<38}", fg='white', nl=False)
                click.secho(f"{sub_value}", fg='green')
        elif isinstance(value, list):
            if len(value) == 1:
                click.secho(f"{formatted_key:<40}", fg='cyan', nl=False)
                click.secho(f"{value[0]}", fg='green')
            else:
                click.secho(f"{formatted_key:<40}", fg='cyan', nl=False)
                click.secho(", ".join(str(item) for item in value[:limit]), fg='green')
        else:
            click.secho(f"{formatted_key:<40}", fg='cyan', nl=False)
            click.secho(f"{str(value)}", fg='green')
    results = attributes.get('results', {})
    if results:
        click.echo('')
        click.echo("Results:")
        for key, value in results.items():
            formatted_key = key.replace('_', ' ').capitalize()
            click.secho(f"{formatted_key:<40}", fg='cyan', nl=False)
            click.secho(f"{str(value)}", fg='green')
