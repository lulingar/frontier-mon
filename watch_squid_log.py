#!/usr/bin/env python
"""
 Squid's access.log format is:
    >a ui un [{d/b/Y:H:M:S +0000}tl] "rm ru HTTP/rv" Hs <st Ss:Sh tr "{X-Frontier-Id}>h" "{If-Modified-Since}>h"
 Meanings are:
    >a      Client source IP address
    tl      Local time. Optional strftime format argument
            default d/b/Y:H:M:S z
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

import time 
import re
import fileinput

#squid_access_re = r"""^(?P<client_ip>\d+(?:\.\d+){3}) (?P<user_ident>\S+) (?P<user_name>\S+) \[(?P<timestamp>\S+ \S+)\] "(?P<method>\S+) (?P<url>\S+) HTTP/(?P<proto_version>\S+)" (?P<code>\d+) (?P<size>\d+) (?P<req_status>[^: ]+):(?P<hierarchy_status>\S+) (?P<resp_time>\d+) "(?P<frontier_id>[^"]+)" "(?P<IMS>[^"]*)"$"""
squid_access_re = r"""^(?P<client_ip>\S+) (?P<user_ident>\S+) (?P<user_name>\S+) \[(?:\S+ \S+)\] "(?P<method>\S+) (?P<url>\S+) HTTP/(?P<proto_version>\S+)" (?P<code>\d+) (?P<size>\d+) (?P<req_status>[^: ]+):(?P<hierarchy_status>\S+) (?P<resp_time>\d+) "(?P<frontier_id>[^"]+)" "(?P<IMS>[^"]*)"$"""
squid_regex = re.compile(squid_access_re)

for line in fileinput.input():

    record = squid_regex.match(line).groupdict()

    """ Parsing the timestamp is unnecessary and wasteful :)
    ts, tz_offset = record['timestamp'].split()
    epoch = int (time.mktime (time.strptime (ts, "%d/%b/%Y:%H:%M:%S")))
    offset = 3600*int(tz_offset[1:3]) + 60*int(tz_offset[3:])
    if tz_offset[0] == '-': epoch -= offset
    else: epoch += offset
    record['timestamp'] = epoch
    """
    record['timestamp'] = time.time()

    #print record['timestamp'], record['client_ip'], record['frontier_id'], record['size']
    print '%.6f' % record['timestamp'],  record['client_ip'], record['frontier_id'], record['size']

#class 

