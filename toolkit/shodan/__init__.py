import collections
import csv
import datetime
import json
import os
import socket
import threading
import time
from _operator import itemgetter

import click
import requests

from toolkit.shodan import helpers
from toolkit.shodan.__main__ import CONVERTERS
from toolkit.shodan.cli.helpers import async_spinner, get_banner_field, escape_data, match_filters, timestr, \
    open_streaming_file
from toolkit.shodan.cli.host import HOST_PRINT
from toolkit.shodan.cli.settings import COLORIZE_FIELDS
from toolkit.shodan.client import Shodan
from toolkit.shodan.exception import APIError

api_key = os.getenv('SHODAN_API_KEY')
if api_key:
    api = Shodan(api_key)
else:
    api = None


def get_api():
    if api:
        return api
    else:
        raise ValueError("API key not set. Please set the SHODAN_API_KEY environment variable.")


def create_alert(name, ip, expires=0):
    try:
        alert = api.create_alert(name, ip, expires)
    except APIError as e:
        raise click.ClickException(e.value)
    click.secho('Successfully created network alert!', fg='green')
    click.secho('Alert ID: {}'.format(alert['id']), fg='cyan')


def edit_alert(aid, ip):
    try:
        alert = api.edit_alert(aid, ip)
    except APIError as e:
        raise click.ClickException(e.value)
    click.echo(alert)


def alerts(aid=None, include_expired=True):
    try:
        results = api.alerts(aid, include_expired)
    except APIError as e:
        raise click.ClickException(e.value)
    if len(results) > 0:
        click.echo(u'# {:14} {:<21} {:<15s}'.format('Alert ID', 'Name', 'IP/ Network'))
        for alert in results:
            click.echo(
                u'{:16} {:<30} {:<35} '.format(
                    click.style(alert['id'], fg='yellow'),
                    click.style(alert['name'], fg='cyan'),
                    click.style(', '.join(alert['filters']['ip']), fg='white')
                ),
                nl=False
            )
            if 'triggers' in alert and alert['triggers']:
                click.secho('Triggers: ', fg='magenta', nl=False)
                click.echo(', '.join(alert['triggers'].keys()), nl=False)
            if 'expired' in alert and alert['expired']:
                click.secho('expired', fg='red')
            else:
                click.echo('')
    else:
        click.echo("You haven't created any alerts yet.")


def delete_alert(aid):
    try:
        api.delete_alert(aid)
    except APIError as e:
        raise click.ClickException(e.value)
    click.echo("Alert deleted")


def alert_triggers():
    try:
        results = api.alert_triggers()
    except APIError as e:
        raise click.ClickException(e.value)
    if len(results) > 0:
        click.secho('The following triggers can be enabled on alerts:', dim=True)
        click.echo('')
        for trigger in sorted(results, key=itemgetter('name')):
            click.secho('{:<12} '.format('Name'), dim=True, nl=False)
            click.secho(trigger['name'], fg='yellow')
            click.secho('{:<12} '.format('Description'), dim=True, nl=False)
            click.secho(trigger['description'], fg='cyan')
            click.secho('{:<12} '.format('Rule'), dim=True, nl=False)
            click.echo(trigger['rule'])
            click.echo('')
    else:
        click.echo("No triggers currently available.")


def enable_alert_trigger(aid, trigger):
    try:
        api.enable_alert_trigger(aid, trigger)
    except APIError as e:
        raise click.ClickException(e.value)
    click.secho('Successfully enabled the trigger: {}'.format(trigger), fg='green')


def disable_alert_trigger(aid, trigger):
    try:
        api.disable_alert_trigger(aid, trigger)
    except APIError as e:
        raise click.ClickException(e.value)
    click.secho('Successfully disabled the trigger: {}'.format(trigger), fg='green')


def convert(input, format, fields=None):
    converter_class = CONVERTERS.get(format)
    if fields:
        if not hasattr(converter_class, 'fields'):
            raise click.ClickException('File format doesnt support custom list of fields')
        converter_class.fields = [item.strip() for item in
                                  fields.split(',')]
    file_size = os.path.getsize(input)
    basename = input.replace('.json.gz', '').replace('.json', '')
    filename = '{}.{}'.format(basename, format)
    fout = open(filename, 'w')
    finished_event = threading.Event()
    progress_bar_thread = threading.Thread(target=async_spinner, args=(finished_event,))
    progress_bar_thread.start()
    converter = converter_class(fout)
    converter.process([input], file_size)
    finished_event.set()
    progress_bar_thread.join()
    if format == 'images':
        click.echo(
            click.style('\rSuccessfully extracted images to directory: {}'.format(converter.dirname), fg='green'))
    else:
        click.echo(click.style('\rSuccessfully created new file: {}'.format(filename), fg='green'))


def count(query, facets=None):
    if query == '':
        raise click.ClickException('Empty search query')
    try:
        results = api.count(query, facets)
    except APIError as e:
        raise click.ClickException(e.value)
    click.echo(results['total'])


def data_list(dataset=None):
    if dataset:
        files = api.data.list_files(dataset)
        for file in files:
            click.echo(click.style(u'{:20s}'.format(file['name']), fg='cyan'), nl=False)
            click.echo(click.style('{:10s}'.format(helpers.humanize_bytes(file['size'])), fg='yellow'), nl=False)
            if file.get('sha1'):
                click.echo(click.style('{:42s}'.format(file['sha1']), fg='green'), nl=False)
            click.echo('{}'.format(file['url']))
    else:
        datasets = api.data.list_datasets()
        for ds in datasets:
            click.echo(click.style('{:15s}'.format(ds['name']), fg='cyan'), nl=False)
            click.echo('{}'.format(ds['description']))


def honeyscore(ip):
    try:
        score = api.labs.honeyscore(ip)
        if score == 1.0:
            click.echo(click.style('Honeypot detected', fg='red'))
        elif score > 0.5:
            click.echo(click.style('Probably a honeypot', fg='yellow'))
        else:
            click.echo(click.style('Not a honeypot', fg='green'))
        click.echo('Score: {}'.format(score))
    except Exception:
        raise click.ClickException('Unable to calculate honeyscore')


def host(ips, history=False, minify=False, filename=None, save=False, output_format='pretty'):
    try:
        host_info = api.host(ips, history, minify)
        if output_format in HOST_PRINT:
            HOST_PRINT[output_format](host_info, history=history)
        else:
            raise click.ClickException(f"Invalid output format: {output_format}")

        if filename or save:
            if save:
                filename = '{}.json.gz'.format(ips)
            if not filename.endswith('.json.gz'):
                filename += '.json.gz'
            fout = helpers.open_file(filename)
            for banner in sorted(host_info['data'], key=lambda k: k['port']):
                if 'placeholder' not in banner:
                    helpers.write_banner(fout, banner)
    except APIError as e:
        raise click.ClickException(e.value)


def info():
    try:
        response = api.info()
    except APIError as e:
        raise click.ClickException(e.value)
    click.echo("""Query credits available: {0}
Scan credits available: {1}""".format(response['query_credits'], response['scan_credits']))


def myip():
    try:
        response = api.tools.myip()
    except APIError as e:
        raise click.ClickException(e.value)
    click.echo(response)


def parse(filenames, color=True, fields='ip_str,port,hostnames,data', filters=None, filename=None, separator=u'\t'):
    fields = [item.strip() for item in fields.split(',')]
    if len(fields) == 0:
        raise click.ClickException('Please define at least one property to show')
    has_filters = len(filters) > 0
    fout = None
    if filename:
        if not has_filters:
            raise click.ClickException(
                'Output file specified without any filters. Need to use filters with this option.')
        if not filename.endswith('.json.gz'):
            filename += '.json.gz'
        fout = helpers.open_file(filename)
    for banner in helpers.iterate_files(filenames):
        row = u''
        if has_filters and not match_filters(banner, filters):
            continue
        if fout:
            helpers.write_banner(fout, banner)
        for i, field in enumerate(fields):
            tmp = u''
            value = get_banner_field(banner, field)
            if value:
                field_type = type(value)
                if field_type == list:
                    tmp = u';'.join(value)
                elif field_type in [int, float]:
                    tmp = u'{}'.format(value)
                else:
                    tmp = escape_data(value)
                if color:
                    tmp = click.style(tmp, fg=COLORIZE_FIELDS.get(field, 'white'))
            if i > 0:
                row += separator
            row += tmp
        click.echo(row)


def radar():
    from toolkit.shodan.cli.worldmap import launch_map
    try:
        launch_map(api)
    except APIError as e:
        raise click.ClickException(e.value)
    except Exception as e:
        raise click.ClickException(u'{}'.format(e))


def scan_list(page=1):
    try:
        scans_info = api.scans(page)
    except APIError as e:
        raise click.ClickException(e.value)
    if len(scans_info) > 0:
        click.echo(u'# {} Scans Total - Showing 10 most recent scans:'.format(scans_info['total']))
        click.echo(u'# {:20} {:<15} {:<10} {:<15s}'.format('Scan ID', 'Status', 'Size', 'Timestamp'))
        for scan in scans_info['matches'][:10]:
            click.echo(
                u'{:31} {:<24} {:<10} {:<15s}'.format(
                    click.style(scan['id'], fg='yellow'),
                    click.style(scan['status'], fg='cyan'),
                    scan['size'],
                    scan['created']
                )
            )
    else:
        click.echo("You haven't yet launched any scans.")


def scan_internet(port, protocol, quiet=False):
    try:
        click.echo('Submitting Internet scan to Shodan...', nl=False)
        scan = api.scan_internet(port, protocol)
        click.echo('Done')
        official_ports = api.ports()
        if port in official_ports:
            click.echo(
                'The requested port is already indexed by Shodan. A new scan for the port has been launched, please subscribe to the real-time stream for results.')
        else:
            filename = '{0}-{1}.json.gz'.format(port, protocol)
            counter = 0
            with helpers.open_file(filename, 'w') as fout:
                click.echo('Saving results to file: {0}'.format(filename))
                done = False
                click.echo('Waiting for data, please stand by...')
                while not done:
                    try:
                        for banner in api.stream.ports([port], timeout=90):
                            counter += 1
                            helpers.write_banner(fout, banner)
                            if not quiet:
                                click.echo('{0:<40} {1:<20} {2}'.format(
                                    click.style(helpers.get_ip(banner), fg=COLORIZE_FIELDS['ip_str']),
                                    click.style(str(banner['port']), fg=COLORIZE_FIELDS['port']),
                                    ';'.join(banner['hostnames']))
                                )
                    except APIError:
                        if done:
                            break
                        scan = api.scan_status(scan['id'])
                        if scan['status'] == 'DONE':
                            done = True
                    except socket.timeout:
                        if done:
                            break
                        scan = api.scan_status(scan['id'])
                        if scan['status'] == 'DONE':
                            done = True
                    except Exception as e:
                        raise click.ClickException(repr(e))
            click.echo('Scan finished: {0} devices found'.format(counter))
    except APIError as e:
        raise click.ClickException(e.value)


def scan_protocols():
    try:
        protocols = api.protocols()
        for name, description in iter(protocols.items()):
            click.echo(click.style('{0:<30}'.format(name), fg='cyan') + description)
    except APIError as e:
        raise click.ClickException(e.value)


def scan_submit(netblocks, wait=20, filename='', force=False, verbose=False):
    try:
        scan = api.scan(netblocks, force=force)
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        click.echo('')
        click.echo('Starting Shodan scan at {} - {} scan credits left'.format(now, scan['credits_left']))
        if verbose:
            click.echo('# Scan ID: {}'.format(scan['id']))
        if wait <= 0:
            click.echo('Scan ID: {}'.format(scan['id']))
            click.echo(
                'Exiting now, not waiting for results. Use the API or website to retrieve the results of the scan.')
        else:
            alert = api.create_alert('Scan: {}'.format(', '.join(netblocks)), netblocks)
            filename = filename.strip()
            fout = None
            if filename != '':
                if not filename.endswith('.json.gz'):
                    filename += '.json.gz'
                fout = helpers.open_file(filename, 'w')
            finished_event = threading.Event()
            progress_bar_thread = threading.Thread(target=async_spinner, args=(finished_event,))
            progress_bar_thread.start()
            hosts = collections.defaultdict(dict)
            done = False
            scan_start = time.time()
            cache = {}
            while not done:
                try:
                    for banner in api.stream.alert(aid=alert['id'], timeout=wait):
                        ip = banner.get('ip', banner.get('ipv6', None))
                        if not ip:
                            continue
                        cache_key = '{}:{}'.format(ip, banner['port'])
                        if cache_key not in cache:
                            hosts[helpers.get_ip(banner)][banner['port']] = banner
                            cache[cache_key] = True
                        if time.time() - scan_start >= 60:
                            scan = api.scan_status(scan['id'])
                            if verbose:
                                click.echo('# Scan status: {}'.format(scan['status']))
                            if scan['status'] == 'DONE':
                                done = True
                                break
                except APIError:
                    if (time.time() - scan_start) < wait:
                        time.sleep(0.5)
                        continue
                    if done:
                        break
                    scan = api.scan_status(scan['id'])
                    if scan['status'] == 'DONE':
                        done = True
                    if verbose:
                        click.echo('# Scan status: {}'.format(scan['status']))
                except socket.timeout:
                    if (time.time() - scan_start) < wait:
                        continue
                    done = True
                except Exception as e:
                    finished_event.set()
                    progress_bar_thread.join()
                    raise click.ClickException(repr(e))
            finished_event.set()
            progress_bar_thread.join()

            def print_field(name, value):
                click.echo('  {:25s}{}'.format(name, value))

            def print_banner(banner):
                click.echo(
                    '    {:20s}'.format(click.style(str(banner['port']), fg='green') + '/' + banner['transport']),
                    nl=False)
                if 'product' in banner:
                    click.echo(banner['product'], nl=False)
                    if 'version' in banner:
                        click.echo(' ({})'.format(banner['version']), nl=False)
                click.echo('')
                if 'ssl' in banner:
                    if 'versions' in banner['ssl']:
                        versions = [version for version in sorted(banner['ssl']['versions']) if
                                    not version.startswith('-')]
                        if len(versions) > 0:
                            click.echo('    |-- SSL Versions: {}'.format(', '.join(versions)))
                    if 'dhparams' in banner['ssl'] and banner['ssl']['dhparams']:
                        click.echo('    |-- Diffie-Hellman Parameters:')
                        click.echo(
                            '        {:15s}{}\n        {:15s}{}'.format('Bits:', banner['ssl']['dhparams']['bits'],
                                                                        'Generator:',
                                                                        banner['ssl']['dhparams']['generator']))
                        if 'fingerprint' in banner['ssl']['dhparams']:
                            click.echo(
                                '        {:15s}{}'.format('Fingerprint:', banner['ssl']['dhparams']['fingerprint']))

            if hosts:
                click.echo('\b ')
                for ip in sorted(hosts):
                    host = next(iter(hosts[ip].items()))[1]
                    click.echo(click.style(ip, fg='cyan'), nl=False)
                    if 'hostnames' in host and host['hostnames']:
                        click.echo(' ({})'.format(', '.join(host['hostnames'])), nl=False)
                    click.echo('')
                    if 'location' in host and 'country_name' in host['location'] and host['location']['country_name']:
                        print_field('Country', host['location']['country_name'])
                        if 'city' in host['location'] and host['location']['city']:
                            print_field('City', host['location']['city'])
                    if 'org' in host and host['org']:
                        print_field('Organization', host['org'])
                    if 'os' in host and host['os']:
                        print_field('Operating System', host['os'])
                    click.echo('')
                    if 'vulns' in host and len(host['vulns']) > 0:
                        vulns = []
                        for vuln in host['vulns']:
                            if vuln.startswith('!'):
                                continue
                            if vuln.upper() == 'CVE-2014-0160':
                                vulns.append(click.style('Heartbleed', fg='red'))
                            else:
                                vulns.append(click.style(vuln, fg='red'))
                        if len(vulns) > 0:
                            click.echo('  {:25s}'.format('Vulnerabilities:'), nl=False)
                            for vuln in vulns:
                                click.echo(vuln + '\t', nl=False)
                            click.echo('')
                    click.echo('  Open Ports:')
                    for port in sorted(hosts[ip]):
                        print_banner(hosts[ip][port])
                        if fout:
                            helpers.write_banner(fout, hosts[ip][port])
                    click.echo('')
            else:
                click.echo(
                    '\bNo open ports found or the host has been recently crawled and cant get scanned again so soon.')
    except APIError as e:
        raise click.ClickException(e.value)
    finally:
        if alert:
            api.delete_alert(alert['id'])


def scan_status(scan_id):
    try:
        scan = api.scan_status(scan_id)
        click.echo(scan['status'])
    except APIError as e:
        raise click.ClickException(e.value)


def search(query, limit=100, fields='ip_str,port,hostnames,data', separator='\t', color=True):
    query = ' '.join(query).strip()
    if query == '':
        raise click.ClickException('Empty search query')
    if limit > 1000:
        raise click.ClickException('Too many results requested, maximum is 1,000')
    fields = [item.strip() for item in fields.split(',')]
    if len(fields) == 0:
        raise click.ClickException('Please define at least one property to show')
    try:
        results = api.search(query, limit=limit, minify=False, fields=fields)
    except APIError as e:
        raise click.ClickException(e.value)
    if results['total'] == 0:
        raise click.ClickException('No search results found')
    output = u''
    for banner in results['matches']:
        row = u''
        for field in fields:
            value = get_banner_field(banner, field)
            if value:
                field_type = type(value)
                if field_type == list:
                    tmp = u';'.join(value)
                elif field_type in [int, float]:
                    tmp = u'{}'.format(value)
                else:
                    tmp = escape_data(value)
                if color:
                    tmp = click.style(tmp, fg=COLORIZE_FIELDS.get(field, 'white'))
                row += tmp
            row += separator
        output += row + u'\n'
    click.echo_via_pager(output)


def stats(query, limit=10, facets='country,org', filename=None):
    query = ' '.join(query).strip()
    if query == '':
        raise click.ClickException('Empty search query')
    facets = facets.split(',')
    facets = [(facet, limit) for facet in facets]
    try:
        results = api.count(query, facets=facets)
    except APIError as e:
        raise click.ClickException(e.value)
    for facet in results['facets']:
        click.echo('Top {} Results for Facet: {}'.format(len(results['facets'][facet]), facet))
        for item in results['facets'][facet]:
            value = u'{}'.format(item['value'])
            click.echo(click.style(u'{:28s}'.format(value), fg='cyan'), nl=False)
            click.echo(click.style(u'{:12,d}'.format(item['count']), fg='green'))
        click.echo('')
    fout = None
    if filename:
        if not filename.endswith('.csv'):
            filename += '.csv'
        fout = open(filename, 'w')
        writer = csv.writer(fout, dialect=csv.excel)
        writer.writerow(['Query', query])
        writer.writerow([])
        row = []
        for facet in results['facets']:
            row.append(facet)
            row.append('')
        writer.writerow(row)
        counter = 0
        has_items = True
        while has_items:
            # pylint: disable=W0612
            row = ['' for i in range(len(results['facets']) * 2)]
            pos = 0
            has_items = False
            for facet in results['facets']:
                values = results['facets'][facet]
                if len(values) > counter:
                    has_items = True
                    row[pos] = values[counter]['value']
                    row[pos + 1] = values[counter]['count']
                pos += 2
            if has_items:
                writer.writerow(row)
            counter += 1


def stream(streamer='https://stream.shodan.io', fields='ip_str,port,hostnames,data', separator='\t', datadir=None,
           asn=None, alert=None, countries=None, custom_filters=None, ports=None, tags=None, vulns=None, limit=-1,
           compresslevel=9, timeout=0, color=True, quiet=False):
    api.stream.base_url = streamer
    fields = [item.strip() for item in fields.split(',')]
    if len(fields) == 0:
        raise click.ClickException('Please define at least one property to show')
    stream_type = []
    if ports:
        stream_type.append('ports')
    if countries:
        stream_type.append('countries')
    if asn:
        stream_type.append('asn')
    if alert:
        stream_type.append('alert')
    if tags:
        stream_type.append('tags')
    if vulns:
        stream_type.append('vulns')
    if custom_filters:
        stream_type.append('custom_filters')
    if len(stream_type) > 1:
        raise click.ClickException(
            'Please use --ports, --countries, --custom, --tags, --vulns OR --asn. You cant subscribe to multiple filtered streams at once.')
    stream_args = None
    if ports:
        try:
            stream_args = [int(item.strip()) for item in ports.split(',')]
        except ValueError:
            raise click.ClickException('Invalid list of ports')
    if alert:
        alert = alert.strip()
        if alert.lower() != 'all':
            stream_args = alert
    if asn:
        stream_args = asn.split(',')
    if countries:
        stream_args = countries.split(',')
    if tags:
        stream_args = tags.split(',')
    if vulns:
        stream_args = vulns.split(',')
    if custom_filters:
        stream_args = custom_filters
    if len(stream_type) == 1:
        stream_type = stream_type[0]
    else:
        stream_type = 'all'

    def _create_stream(name, args, timeout):
        return {
            'all': api.stream.banners(timeout=timeout),
            'alert': api.stream.alert(args, timeout=timeout),
            'asn': api.stream.asn(args, timeout=timeout),
            'countries': api.stream.countries(args, timeout=timeout),
            'custom_filters': api.stream.custom(args, timeout=timeout),
            'ports': api.stream.ports(args, timeout=timeout),
            'tags': api.stream.tags(args, timeout=timeout),
            'vulns': api.stream.vulns(args, timeout=timeout),
        }.get(name, 'all')

    stream = _create_stream(stream_type, stream_args, timeout=timeout)
    counter = 0
    quit = False
    last_time = timestr()
    fout = None
    if datadir:
        fout = open_streaming_file(datadir, last_time, compresslevel)
    while not quit:
        try:
            for banner in stream:
                if limit > 0:
                    counter += 1
                    if counter > limit:
                        quit = True
                        break
                if datadir:
                    cur_time = timestr()
                    if cur_time != last_time:
                        last_time = cur_time
                        fout.close()
                        fout = open_streaming_file(datadir, last_time)
                    helpers.write_banner(fout, banner)
                if not quiet:
                    row = u''
                    for field in fields:
                        value = get_banner_field(banner, field)
                        if value:
                            field_type = type(value)
                            if field_type == list:
                                tmp = u';'.join(value)
                            elif field_type in [int, float]:
                                tmp = u'{}'.format(value)
                            else:
                                tmp = escape_data(value)
                            if color:
                                tmp = click.style(tmp, fg=COLORIZE_FIELDS.get(field, 'white'))
                            row += tmp
                        row += separator
                    click.echo(row)
        except requests.exceptions.Timeout:
            raise click.ClickException('Connection timed out')
        except KeyboardInterrupt:
            quit = True
        except APIError as e:
            raise click.ClickException(e.value)
        except Exception:
            time.sleep(1)
            stream = _create_stream(stream_type, stream_args, timeout=timeout)


def trends(query, facets='', filename=None, save=False):
    query = ' '.join(query).strip()
    facets = facets.strip()
    if query == '':
        raise click.ClickException('Empty search query')
    parsed_facets = []
    for facet in facets.split(','):
        if not facet:
            continue
        parts = facet.strip().split(":")
        if len(parts) > 1:
            parsed_facets.append((parts[0], parts[1]))
        else:
            parsed_facets.append((parts[0]))
    try:
        results = api.trends.search(query, facets=parsed_facets)
    except APIError as e:
        raise click.ClickException(e.value)
    if results['total'] == 0:
        raise click.ClickException('No search results found')
    result_facets = []
    if results.get("facets"):
        result_facets = list(results["facets"].keys())
    if filename or save:
        if not filename:
            filename = '{}-trends.json.gz'.format(query.replace(' ', '-'))
        elif not filename.endswith('.json.gz'):
            filename += '.json.gz'
        with helpers.open_file(filename) as fout:
            for index, match in enumerate(results['matches']):
                if result_facets:
                    match["facets"] = {}
                    for facet in result_facets:
                        match["facets"][facet] = results['facets'][facet][index]['values']
                line = json.dumps(match) + '\n'
                fout.write(line.encode('utf-8'))
        click.echo(click.style(u'Saved results into file {}'.format(filename), 'green'))
    output = u''
    if result_facets:
        for index, match in enumerate(results['matches']):
            output += click.style(match['month'] + u'\n', fg='green')
            if match['count'] > 0:
                for facet in result_facets:
                    output += click.style(u'  {}\n'.format(facet), fg='cyan')
                    for bucket in results['facets'][facet][index]['values']:
                        output += u'    {:60}{}\n'.format(click.style(bucket['value'], bold=True),
                                                          click.style(u'{:20,d}'.format(bucket['count']), fg='green'))
            else:
                output += u'{}\n'.format(click.style('N/A', bold=True))
    else:
        for index, match in enumerate(results['matches']):
            output += u'{:20}{}\n'.format(click.style(match['month'], bold=True),
                                          click.style(u'{:20,d}'.format(match['count']), fg='green'))
    click.echo_via_pager(output)


def domain_info(domain, details=False, save=False, history=False, type=None):
    try:
        info = api.dns.domain_info(domain, history=history, type=type)
    except APIError as e:
        raise click.ClickException(e.value)
    hosts = {}
    if details:
        ips = [record['value'] for record in info['data'] if record['type'] in ['A', 'AAAA']]
        ips = set(ips)
        fout = None
        if save:
            filename = u'{}-hosts.json.gz'.format(domain)
            fout = helpers.open_file(filename)
        for ip in ips:
            try:
                hosts[ip] = api.host(ip)
                if fout:
                    for banner in hosts[ip]['data']:
                        if 'placeholder' not in banner:
                            helpers.write_banner(fout, banner)
            except APIError:
                pass
    if save:
        filename = u'{}.json.gz'.format(domain)
        fout = helpers.open_file(filename)
        for record in info['data']:
            helpers.write_banner(fout, record)
    click.secho(info['domain'].upper(), fg='green')
    click.echo('')
    for record in info['data']:
        click.echo(
            u'{:32}  {:14}  {}'.format(
                click.style(record['subdomain'], fg='cyan'),
                click.style(record['type'], fg='yellow'),
                record['value']
            ),
            nl=False,
        )
        if record['value'] in hosts:
            host = hosts[record['value']]
            click.secho(u' Ports: {}'.format(', '.join([str(port) for port in sorted(host['ports'])])), fg='blue',
                        nl=False)
        click.echo('')


def download(filename, query, fields=None, limit=1000):
    query = ' '.join(query).strip()
    if query == '':
        raise click.ClickException('Empty search query')
    filename = filename.strip()
    if filename == '':
        raise click.ClickException('Empty filename')
    if not filename.endswith('.json.gz'):
        filename += '.json.gz'
    if fields is not None:
        fields = [item.strip() for item in fields.split(',')]
    try:
        total = api.count(query)['total']
        info = api.info()
    except Exception:
        raise click.ClickException('The Shodan API is unresponsive at the moment, please try again later.')
    click.echo('Search query:\t\t\t{}'.format(query))
    click.echo('Total number of results:\t{}'.format(total))
    click.echo('Query credits left:\t\t{}'.format(info['unlocked_left']))
    click.echo('Output file:\t\t\t{}'.format(filename))
    if limit > total:
        limit = total
    if limit <= 0:
        limit = total
    with helpers.open_file(filename, 'w') as fout:
        count = 0
        try:
            cursor = api.search_cursor(query, minify=False, fields=fields)
            with click.progressbar(cursor, length=limit) as bar:
                for banner in bar:
                    helpers.write_banner(fout, banner)
                    count += 1

                    if count >= limit:
                        break
        except Exception:
            pass
        if count < limit:
            click.echo(click.style('Notice: fewer results were saved than requested', 'yellow'))
        click.echo(click.style(u'Saved {} results into file {}'.format(count, filename), 'green'))
