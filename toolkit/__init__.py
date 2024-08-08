import click

from . import shodan
from . import urlscan
from . import virustotal

__all__ = ['shodan', 'urlscan', 'virustotal', 'investigate_url']


def investigate_url(url, facets='country,vuln'):
    try:
        # Submit URL scan request to urlscan
        scan_uuid = urlscan.investigate_url(url, private=False, standalone=False)
        click.echo('')
        click.secho("Fetching information from urlscan.io...", fg='magenta')
        urlscan_result = urlscan.get_report_data(scan_uuid, standalone=False)
        click.echo('')
        urlscan.print_report(urlscan_result)

        # Scan URL with VirusTotal
        click.secho("\nFetching information from VirusTotal...", fg='magenta')
        vt_result = virustotal.url_scan(url, standalone=False)
        click.echo('')
        virustotal.print_object(vt_result)

        # Extract IP address from URLScan report to fetch information from Shodan
        ip_address = urlscan_result.get("page", {}).get("ip")
        if ip_address:
            click.secho("\nFetching information from Shodan...", fg='magenta')
            click.echo('')
            shodan.host(ip_address)
            click.echo('')
            shodan.stats(ip_address, facets)

    except click.ClickException as e:
        click.secho(f"Error: {e}", fg='red')
