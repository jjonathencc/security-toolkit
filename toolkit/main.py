import click
from toolkit.urlscan import scan as scan_url


@click.command()
@click.argument('url')
def main(url):
    """Scan a URL using various security tools."""
    result = scan_url(url)
    print(result)
    # Add calls to other tools here


if __name__ == '__main__':
    main()
