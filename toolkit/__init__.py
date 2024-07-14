from . import shodan
from . import urlscan
from . import virustotal

__all__ = ['shodan', 'urlscan', 'virustotal', 'scanurl']


def scanurl(url):
    print("URLScan Result:")
    investigation = urlscan.investigate(url, False, False)
    result = urlscan.get_result_data(investigation.get('scan_uuid'), False)
    print_formatted(result)

    print("\nVirusTotal Result:")
    vt_result = virustotal.get_url_analysis(url)
    filtered_vt_result = filter_vt_result(vt_result.to_dict())
    print_formatted(filtered_vt_result)


def filter_vt_result(result):
    filtered_result = result.copy()

    if 'attributes' in filtered_result:
        attributes = filtered_result['attributes']

        # Count the number of items in 'last_analysis_results'
        if 'last_analysis_results' in attributes:
            del attributes['last_analysis_results']

        # Show only the first 10 'outgoing_links'
        if 'outgoing_links' in attributes:
            attributes['outgoing_links'] = attributes['outgoing_links'][:10]

        filtered_result['attributes'] = attributes

    return filtered_result


def print_formatted(data, indent=0):
    for key, value in data.items():
        if isinstance(value, dict):
            print(' ' * indent + f"{key}:")
            print_formatted(value, indent + 4)
        elif isinstance(value, list):
            print(' ' * indent + f"{key}:")
            for item in value:
                if isinstance(item, dict):
                    print_formatted(item, indent + 4)
                else:
                    print(' ' * (indent + 4) + str(item))
        else:
            print(' ' * indent + f"{key}: {value}")
