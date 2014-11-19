#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys

from datetime import datetime, timedelta

"""
 Squid's access.log format is:
    >a ui un [{d/b/Y:H:M:S.f +0000}tl] "rm ru HTTP/rv" Hs <st Ss:Sh tr
    >"{X-Frontier-Id}>h %{cvmfs-info}>h" "%{Referer}>h" "%{User-Agent}>h"
 Meanings are:
    >a      Client source IP address
    tl      Local time. Optional strftime format argument
            default d/b/Y:H:M:S.f z
    tr      Response time (milliseconds)
    >h      Request header. Optional header name argument
            on the format header[:[separator]element]
    <h      Reply header. Optional header name argument
            as for >h
    un      User name
    ui      User name from ident
    ue      User name from external acl helper
    Hs      HTTP status code
    Ss      Squid request status (TCP_MISS etc)
    Sh      Squid hierarchy status (DEFAULT_PARENT etc)
    rm      Request method (GET/POST etc)
    ru      Request URL
    rv      Request protocol version
    <st     Reply size including HTTP headers
"""
squid_access_re = re.compile(r"""^(?P<who>\S+) (?P<user_ident>\S+) (?P<user_name>\S+) \[(?P<timestamp>\S+ \S+)\] "(?P<method>\S+) (?P<url>\S+) HTTP/(?P<proto_version>\S+)" (?P<http_code>\d+) (?P<size>\d+) (?P<req_status>[^: ]+):(?P<hierarchy_status>\S+) (?P<duration>\d+) "(?P<client_id>[^"]+)" "(?P<referer>[^"]+)" "(?P<user_agent>[^"]+)"$""")
squid_url_re = re.compile(r'[^/]+[/]+(?P<server>[^/:]+)[:]*[^/]*/(?P<data>\S+)')
squid_data_re = re.compile(r'(?P<servlet>[^/]+)/(?P<query_name>[^/]+)[/?](?P<query>\S+)')

def parse_log_line (line):

    match = squid_access_re.match(line.rstrip())

    if match:
        record = match.groupdict()

        timestamp = parse_squid_timedate(record.pop('timestamp'))
        epoch_ms = datetime_epoch_ms(timestamp)
        record['timestamp'] = epoch_ms

        client_id = record.pop('client_id')
        client_info = process_client_id(client_id)
        record.update(client_info)

        record['size'] = int(record['size'])
        record['duration'] = int(record['duration'])
        record['http_code'] = int(record['http_code'])

        url = record.pop('url')
        url_match = squid_url_re.match(url)
        if url_match:
            record.update( url_match.groupdict())
            data = record.pop('data')

            data_match = squid_data_re.match(data)
            if data_match:
                record.update(data_match.groupdict())

                return record
        else:
            data = '_empty_'

        record['query'] = data
        record['query_name'] = "primitive"

        return record

    print "No record:"
    print line

    return None

def process_client_id(client_id):

    client_info = {}
    if client_id.endswith(' -'):
        client_info['client_type'] = "frontier"
        frontier_id = client_id[:-2]
        frontier_info = process_frontier_id(frontier_id)
        client_info.update(frontier_info)

    elif client_id.startswith('- '):
        client_info['client_type'] = "cvmfs"
        cvmfs_id = client_id[2:]
        cvmfs_info = process_cvmfs_id(cvmfs_id)
        client_info.update(cvmfs_info)

    return client_info

def process_frontier_id(frontier_id):

    frontier_info = {}

    if 'opportunistic probe' in frontier_id:
        frontier_info['fid_sw_release'] = frontier_id
    else:
        frontier_id_parts = frontier_id.split()

        if len(frontier_id_parts) > 1:
            frontier_info['fid_sw_release'] = frontier_id_parts[0]
            frontier_info['fid_sw_version'] = frontier_id_parts[1]

            if len(frontier_id_parts) > 2:
                if frontier_id_parts[0] != "SLS_probe":
                    frontier_info['fid_pid'] = frontier_id_parts[2]
            if len(frontier_id_parts) > 3:
                frontier_info['fid_uid'] = frontier_id_parts[3]
                frontier_info['fid_userdn'] = ' '.join(frontier_id_parts[4:])
        else:
            frontier_info['fid_sw_release'] = frontier_id_parts[0]

    return frontier_info

def process_cvmfs_id(cvmfs_id):

    return {'cvmfs_info': cvmfs_id}

month_abbreviations = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
                       'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
                       'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}

def parse_squid_timedate (timestamp_str):

    try:
        td, tz = timestamp_str.split()

        day = int(td[0:2])
        month = month_abbreviations[td[3:6]]
        year = int(td[7:11])
        hour = int(td[12:14])
        minute = int(td[15:17])
        second = float(td[18:])

        ofs_sign, ofs_h, ofs_m = tz[0], int(tz[1:3]), int(tz[3:])

        if ofs_sign == '-':
            ofs_sign = 1
        else:
            ofs_sign = -1
        ofs_seconds = ofs_sign * 60 * (60*ofs_h + ofs_m)
        offset = timedelta(seconds=ofs_seconds)

        microsecond = int(1e6*(second - int(second)))
        naive = datetime(year, month, day, hour, minute,
                         int(second), microsecond)

        return naive + offset

    except Exception, ex:
        print ">>> TS error:", timestamp_str
        return None

epoch_0 = datetime(1970, 1, 1)

def datetime_epoch_ms(dt):

    x = dt - epoch_0
    return (1000 * (x.days*86400 + x.seconds)) + x.microseconds/1000

# Simple console program
def main ():

    import json
    import pprint

    for line in sys.stdin:

        record = parse_log_line(line)

        if record is not None:
            pprint.pprint(json.dumps(record), indent=4)

    return 0

if __name__ == "__main__":
    sys.exit(main())
