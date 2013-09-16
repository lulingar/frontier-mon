import base64
import collections
import fileinput
import os
import re
import socket
import sys
import threading
import time
import zlib

from Utils import current_utc_time_usecs, lru_cache, lfu_cache, parse_utc_time_usecs

def main():

    tw = TomcatWatcher(10, True)

    try:
        for line in fileinput.input():

            tw.advance_records (line)
             

    except (KeyboardInterrupt, SystemExit):
        pass

    return 0
            

"""
 Tomcat's access.log format is:
    *  <servlet_name> <timestamp> id=<id> <payload>
      Ex:
         FrontierPrep 08/05/13 19:34:35.622 CEST +0200 id=293476 <payload> 

 where the <payload> is composed of several kinds of messages:
    *  servlet_version:<number> start threads:<number> <query_data> <client_data> <forwarding_data>
      Ex:
       servlet_version:3.30 start threads:1 query /type=frontier_request:1:DEFAULT&encoding=BLOBzip5&p1=<very_long_string_encoding_the_query> raddr 127.0.0.1 frontier-id: CMSSW_5_3_8_patch1 2.8.5 5258 puigh(524) Darren Puigh via: 1.0 vocms213.cern.ch:8000 (squid/frontier-squid-2.7.STABLE9-16.1) x-forwarded-for: 128.146.38.254
    *  DB query finished msecs=<number>
    *  rows=<number>, full size=<number>
    *  DB connection released remaining=<number>
    *  stop threads=<number> msecs=<number>
    *  Error <error message>
    *  Client disconnected while processing payload 0: ClientAbortException ... 
    *  SQL <SQL query>
    *  Acquiring DB connection [lock]
    *  Executing DB query
    *  [several others, to be ignored in the meantime]

In any of these cases, the <id> can be appended with a "-ka", which means the connection was attempted to be Kept Alive.

The other kind of entry is that of an exception. An example is:
    java.lang.Exception: X-frontier-id header missing
            at gov.fnal.frontier.Frontier.logClientDesc(Frontier.java:429)
            at gov.fnal.frontier.Frontier.<init>(Frontier.java:261)
            at gov.fnal.frontier.FrontierServlet.service(FrontierServlet.java:123)
            at javax.servlet.http.HttpServlet.service(HttpServlet.java:723)
            <several more of these lines>
    <a blank line>
"""

class TomcatWatcher(object):

    regex_general = re.compile(r'^(?P<servlet>\S+) (?P<timestamp>(?:\S+ ){4})id=(?P<id>\S+) (?P<payload>.*)')
    regex_start = re.compile(r'servlet_version:(?P<version>\S+) start threads:(?P<threads_start>\d+) query (?P<query>\S+) raddr (?P<who>\S+) frontier-id: (?P<complement>.*)')
    regex_start_complement = re.compile(r'frontier-id: ')
    regex_dbacq = re.compile(r'DB connection acquired active=(?P<active_acq>\d+) msecs=(?P<msecs_acq>\d+)')
    regex_dbfin = re.compile(r'DB query finished msecs=(?P<msecs_finish>\d+)')
    regex_rowssize = re.compile(r'rows=(?P<rows>\d+), full size=(?P<size>\d+)')
    regex_threads = re.compile(r'stop threads=(?P<threads_stop>\d+) msecs=(?P<msecs_stop>\d+)')
    regex_error = re.compile(r'Error (?P<error>.*)')
    regex_client = re.compile(r'Client (?P<client>.*)')
    regex_sql = re.compile(r'SQL (?P<sql>.*)')
    regex_acq = re.compile(r'Acquiring DB (?P<dbacq>.*)')
    regex_exe = re.compile(r'Executing DB query')
    regex_kaacq = re.compile(r'DB acquire sent keepalive (?P<kaacq>\d+)')

    status_queued = 'queued'
    status_exec = 'executing'
    status_stop = 'finished'

    finish_normal = 'ok'
    finish_timeout = 'timed-out'
    finish_error = 'aborted'

    def __init__ (self, window_length_secs, use_timestamps_in_log=True):

        self.use_timestamps_in_log = use_timestamps_in_log

        self.window_length_V = int (1e6 * window_length_secs)
        self.oldest_start_time = float("inf")
        self.newest_stop_time = 0

        self.history_H = collections.deque()
        self.data_D = {}

        self.last_id = None
        

    def parse_log_line (self, line_in):

        line = line_in.strip()
        if not line: return

        general_match = self.regex_general.match(line)

        if general_match:
            
            record = general_match.groupdict()
            id = record.pop('id')

            timestamp_log = record.pop('timestamp')
            if self.use_timestamps_in_log:
                timestamp = parse_utc_time_usecs (timestamp_log[:-12])
            else:
                timestamp = current_utc_time_usecs()

            payload = record.pop('payload')
           
            match = self.regex_start.match(payload)
            if match:
                if self.oldest_start_time > timestamp: 
                    self.oldest_start_time = timestamp
                    print "New oldest start:", self.oldest_start_time

                record['time_start'] = timestamp 
                record['state'] = self.status_queued 
                record['keepalives'] = 0
                #TODO: Process complement
                record.update (match.groupdict())
                self.data_D[id] = record
                self.history_H.append(id)
                return
           
            if id in self.data_D:
                record = self.data_D[id]
                self.last_id = id
            else:
                return

            match = self.regex_dbacq.match(payload)
            if match:
                record.update (match.groupdict())
                return
            
            match = self.regex_dbfin.match(payload)
            if match:
                record.update (match.groupdict())
                return
            
            match = self.regex_rowssize.match(payload)
            if match:
                record.update (match.groupdict())
                return
            
            match = self.regex_threads.match(payload)
            if match:
                self.finish_record (id, timestamp, self.finish_normal)
                record.update (match.groupdict())
                return
            
            match = self.regex_error.match(payload)
            if match:
                if 'error' in record:
                    print 'Existing error for id %s: %s' % (id, record['error'])
                    print 'New error:', match.group('error')
                record.update (match.groupdict())
                return
            
            match = self.regex_client.match(payload)
            if match:
                if 'client_msg' not in record:
                    record['client_msg'] = []
                record['client_msg'].append (match.group('client'))
                return
            
            match = self.regex_sql.match(payload)
            if match:
                record.update (match.groupdict())
                return
            
            match = self.regex_acq.match(payload)
            if match:
                record.update (match.groupdict())
                return
            
            match = self.regex_exe.match(payload)
            if match:
                record['state'] = self.status_exec
                return
            
            match = self.regex_kaacq.match(payload)
            if match:
                record['keepalives'] += int(match.group('kaacq'))
                return
            
            #print "No match!", line

        else:
            if 'xception' in line:
                if self.last_id:
                    id = self.last_id
                else:
                    return

                self.finish_record (id, timestamp, self.finish_error) 
    
            elif line.startswith('at '): 
                return

            else:
                print "Unforseen line:", line
        

    def update (self):
        
        current_timespan_usecs = self.newest_stop_time - self.oldest_start_time
        while current_timespan_usecs > self.window_length_V:
            dropped_id = self.history_H.popleft()
            dropped_record = self.data_D.pop(dropped_id)
            self.oldest_start_time = dropped_record['time_start']
            current_timespan_usecs = self.newest_stop_time - self.oldest_start_time

    def finish_record (self, id, timestamp, finish_mode):

        self.data_D[id]['time_stop'] = timestamp 
        self.data_D[id]['state'] = self.status_stop
        self.data_D[id]['finish_mode'] = finish_mode 

        if self.newest_stop_time < timestamp: 
            self.newest_stop_time = timestamp


    def advance_records(self, line_in):

        self.parse_log_line(line_in)
        self.update()
        
        

if __name__ == "__main__":
    sys.exit(main())

