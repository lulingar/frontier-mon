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

import fileinput
import re
import sys
import threading
import time

from Utils import current_utc_time_usecs, TimeWindowedRecord

user_stats = TimeWindowedRecord (60)
query_stats = TimeWindowedRecord (60)

def main ():

    threads_signal = threading.Event()

    threads = [threading.Thread (name='log', target=log_thread, args=(threads_signal,)),
               threading.Thread (name='print', target=print_thread, args=(threads_signal,))]

    for thread in threads: thread.start()

    try:
        while True: time.sleep(100)
    except (KeyboardInterrupt, SystemExit):
        print "Exitting...",
        threads_signal.set()
        for thread in threads: thread.join()
        print "success!"

    return 0


def log_thread (signal):

    for line in fileinput.input():

        record = parse_log_line (line)
        
        if 'fid_userdn' in record:

            user_stats.event (record['fid_userdn'])
            query_stats.event ("%s#%s" % (record['servlet'], record['query']))

        if signal.isSet():
            break

def print_thread (signal):
    
    while not signal.isSet():
        signal.wait(2)

        print chr(27) + "[2J"
        print "At", time.strftime("%d/%b/%Y %H:%M:%S"), "for the last %.2f seconds:" % (query_stats.current_window_length_secs())

        print "Query stats:" 
        for query, amount in query_stats.most_frequent(10):
            print "  -> (%d): %s" % (amount, query)

        print "User stats:"
        for user, amount in user_stats.most_frequent(10):
            print "  -> (%d): %s" % (amount, user)

        #print record['timestamp'], '(%s)' % record['fid_userdn'], record['client_ip'], record['fid_sw_release'], record['size'], record['fid_uid'], '>', record['server'], record['query'], record['servlet']



squid_access_re = r"""^(?P<client_ip>\S+) (?P<user_ident>\S+) (?P<user_name>\S+) \[(?:\S+ \S+)\] "(?P<method>\S+) (?:[^/]+)[/]+(?P<server>[^/]+)/(?P<servlet>[^/]+)/(?P<query_name>[^/]+)[/?](?P<query>\S+) HTTP/(?P<proto_version>\S+)" (?P<code>\d+) (?P<size>\d+) (?P<req_status>[^: ]+):(?P<hierarchy_status>\S+) (?P<resp_time>\d+) "(?P<frontier_id>[^"]+)" "(?P<IMS>[^"]*)"$"""
squid_regex = re.compile(squid_access_re)

def parse_log_line (line):

    record = squid_regex.match(line).groupdict()

    record['timestamp'] = current_utc_time_usecs()

    frontier_id_parts = record['frontier_id'].split()
    record.pop('frontier_id')

    record['fid_sw_release'] = frontier_id_parts[0]
    record['fid_sw_version'] = frontier_id_parts[1]

    if len(frontier_id_parts) > 2:
        record['fid_pid'] = frontier_id_parts[2]
    if len(frontier_id_parts) > 3:
        record['fid_uid'] = frontier_id_parts[3]
        record['fid_userdn'] = ' '.join(frontier_id_parts[4:])
    
    return record


if __name__ == '__main__':
    sys.exit(main())
