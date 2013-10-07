import re
import collections

import numpy as np
import pandas as pd

from Utils import RecordTable, parse_utc_time_usecs, current_utc_time_usecs, decode_frontier, get_hostname


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

    record_variables = {"servlet": str,
                        "version": str,
                        "query": str,
                        "who": str,
                        "error": str,
                        "sql": str,
                        "dbacq": str,
                        "state": str,
                        "fid": str,
                        "forward": str,
                        "via": str,
                        "finish_mode": str,
                        "if-modified-since": str,
                        "other": str,
                        "threads_start": int,
                        "threads_stop": int,
                        "msecs_acq": int,
                        "msecs_finish": int,
                        "msecs_stop": int,
                        "rows": int,
                        "size": int,
                        "active_acq": int,
                        "kaacq": int,
                        "keepalives": int,
                        "time_start": int,
                        "duration": int}

    regex_general = re.compile(r'^(?P<servlet>\S+) (?P<timestamp>(?:\S+ ){4})id=(?P<key>\S+) (?P<payload>.*)')
    regex_start = re.compile(r'servlet_version:(?P<version>\S+) start threads:(?P<threads_start>\d+) query (?P<query>\S+) raddr (?P<who>\S+) frontier-id: (?P<complement>.*)')
    regex_dbacq = re.compile(r'DB connection acquired active=(?P<active_acq>\d+) msecs=(?P<msecs_acq>\d+)')
    regex_dbfin = re.compile(r'DB query finished msecs=(?P<msecs_finish>\d+)')
    regex_rowssize = re.compile(r'rows=(?P<rows>\d+), full size=(?P<size>\d+)')
    regex_threads = re.compile(r'stop threads=(?P<threads_stop>\d+) msecs=(?P<msecs_stop>\d+)')
    regex_error = re.compile(r'Error (?P<error>.*)')
    regex_client = re.compile(r'Client (?P<client>.*)')
    regex_sql = re.compile(r'SQL (?P<sql>.*)')
    regex_acq = re.compile(r'Acquiring DB (?P<dbacq>.*)')
    regex_exe = re.compile(r'Executing DB query')
    regex_kaacq = re.compile(r'DB (\S+) sent keepalive (?P<kaacq>\d+)')
    regex_prc = re.compile(r'response was precommitted')
    regex_ims_q = re.compile(r'if-modified-since: (?:(?:\S+ )*)')
    regex_ims_qng = re.compile(r'getting last-modified time of (?:(?:\S+ )*)')
    regex_ims_ret = re.compile(r'last-modified time: (?:(?:\S+ )*)')
    regex_ims_h = re.compile(r'using cached last-modified time of (?:(?:\S+ )*)')
    regex_ims_nc = re.compile(r'not modified (cached)')
    regex_ims_n = re.compile(r'not modified')

    status_queued = 'queued'
    status_exec = 'executing'
    status_stop = 'finished'
    status_precom = 'precommitted'

    finish_normal = 'ok'
    finish_timeout = 'timed-out'
    finish_error = 'aborted'

    IMS_not_mod = 'not modified'
    IMS_queried = 'queried'
    IMS_querying = 'querying'
    IMS_return = 'returned'
    IMS_cachehit = 'cache hit'
    IMS_not_mod_cached = 'not modified (cached)'

    ims_update = ( (regex_ims_h, IMS_cachehit),
                   (regex_ims_n, IMS_not_mod),
                   (regex_ims_nc, IMS_not_mod_cached),
                   (regex_ims_ret, IMS_return),
                   (regex_ims_q, IMS_queried),
                   (regex_ims_qng, IMS_querying), )

    to_omit = ["don't know how to query timestamp for table dual",
               'DB connection released remaining=']

    def __init__ (self, window_length_secs, use_timestamps_in_log=True):

        self.use_timestamps_in_log = use_timestamps_in_log

        self.window_length_V = int( 1e6 * window_length_secs)
        self.oldest_start_time = float("inf")
        self.newest_stop_time = 0

        self.history_H = collections.deque()
        initial_rows_estimation = 100 * int(window_length_secs)
        self.data_D = RecordTable( self.record_variables,
                                   initial_rows = initial_rows_estimation,
                                   datatype = int )
        self._last_key = None
        self._last_timestamp = None

    def parse_log_line (self, line_in):

        line = line_in.strip()
        if not line: return

        general_match = self.regex_general.match(line)

        if general_match:
            record = general_match.groupdict()

            servlet = record['servlet']
            id_raw = record.pop('key').replace('-ka', '')
            key = servlet + id_raw

            timestamp_log = record.pop('timestamp')
            if self.use_timestamps_in_log:
                timestamp = parse_utc_time_usecs (timestamp_log[:-12])
            else:
                timestamp = current_utc_time_usecs()
            self._last_timestamp = timestamp

            payload = record.pop('payload')

            match = self.regex_start.match(payload)
            if match:
                if self.oldest_start_time > timestamp:
                    self.oldest_start_time = timestamp

                record.update (match.groupdict())
                record['time_start'] = timestamp
                record['threads_start'] = int(record['threads_start'])
                record['state'] = self.status_queued
                record['keepalives'] = 0
                record['who'] = get_hostname( record['who'])
                record['query'] = decode_frontier( record['query'])

                complement = record.pop('complement')
                parts = complement.split(':')
                record['fid'] = parts[0].replace(' x-forwarded-for', '')\
                                        .replace(' via', '')
                if len(parts) > 1:
                    if parts[-2].endswith(' x-forwarded-for'):
                        record['forward'] = parts[-1]
                    record['via'] = ':'.join(parts[1:-1]).replace('x-forwarded-for', '')

                self.data_D[key] = record
                self.history_H.append (key)
                return

            if key in self.data_D:
                self._last_key = key
            else:
                return

            match = self.regex_dbacq.match(payload)
            if match:
                update = match.groupdict()
                update['active_acq'] = int(update['active_acq'])
                update['msecs_acq'] = int(update['msecs_acq'])
                self.data_D.modify (key, update)
                return

            match = self.regex_dbfin.match(payload)
            if match:
                update = match.groupdict()
                update['msecs_finish'] = int(update['msecs_finish'])
                self.data_D.modify (key, update)
                return

            match = self.regex_rowssize.match(payload)
            if match:
                update = match.groupdict()
                update['rows'] = int(update['rows'])
                update['size'] = int(update['size'])
                self.data_D.modify (key, update)
                return

            match = self.regex_threads.match(payload)
            if match:
                update = match.groupdict()
                update['msecs_stop'] = int(update['msecs_stop'])
                update['threads_stop'] = int(update['threads_stop'])
                self.data_D.modify (key, update)
                self.finish_record (key, timestamp, self.finish_normal)
                return

            match = self.regex_sql.match(payload)
            if match:
                update = match.groupdict()
                self.data_D.modify (key, update)
                return

            match = self.regex_acq.match(payload)
            if match:
                update = match.groupdict()
                self.data_D.modify (key, update)
                return

            match = self.regex_exe.match(payload)
            if match:
                update = {'state': self.status_exec}
                self.data_D.modify (key, update)
                return

            match = self.regex_prc.match(payload)
            if match:
                update = {'state': self.status_precom}
                self.data_D.modify (key, update)
                return

            match = self.regex_kaacq.match(payload)
            if match:
                record = self.data_D[key]
                update = {'keepalives': int(match.group('kaacq'))}
                self.data_D.modify (key, update)
                return

            match = self.regex_error.match(payload)
            if match:
                update = match.groupdict()
                self.data_D.modify (key, update)
                return

            match = self.regex_client.match(payload)
            if match:
                record = self.data_D[key]
                if 'client' in record:
                    update = match.groupdict()
                    print 'Existing client message for id %s: %s' % (key, record['client'])
                    print 'New error:', match.group('client')
                #self.data_D.modify (key, update)
                return

            for regex_, code_ in self.ims_update:
                match = regex_.match(payload)
                if match:
                    update = {'if-modified-since': code_}
                    self.data_D.modify (key, update)
                    return

            # Default
            if not any([msg in payload for msg in self.to_omit]):
                update = {'other': payload}
                self.data_D.modify (key, update)
                print key, update
                return

        else:
            if 'xception' in line:
                if self._last_key:
                    key = self._last_key
                    timestamp = self._last_timestamp
                else:
                    return

                self.finish_record (key, timestamp, self.finish_error)

            elif line.startswith('at '):
                return
            else:
                print "Unforseen line:", line

    def finish_record (self, key, timestamp, finish_mode):

        us_to_ms = 1e-3
        start_time = self.data_D.render_record( key, 'time_start')

        update = {'duration': (timestamp - start_time)*us_to_ms,
                  'state': self.status_stop,
                  'finish_mode': finish_mode}
        self.data_D.modify( key, update)

        if self.newest_stop_time < timestamp:
            self.newest_stop_time = timestamp

    def update (self):

        current_timespan_usecs = self.newest_stop_time - self.oldest_start_time
        while current_timespan_usecs > self.window_length_V:
            dropped_key = self.history_H.popleft()
            self.oldest_start_time = self.data_D.render_record (dropped_key, 'time_start')
            del self.data_D[dropped_key]
            current_timespan_usecs = self.newest_stop_time - self.oldest_start_time

    def advance_records (self, line_in):

        self.parse_log_line(line_in)
        self.update()

    def clear(self):
        self.data_D.clear()
        self.history_H.clear()

    def current_window_length_secs (self):

        current_timespan_usecs = self.newest_stop_time - self.oldest_start_time
        return current_timespan_usecs * 1e-6

    def __len__(self):
        return len(self.history_H)

def count_sum_stats (dataframe, group_fields, out_fields, quantile, elements_per_group):

    aggregators = [('sum', np.sum), ('max', np.max),
                   ('count', len), ('mean', np.mean),
                   ('std-dev', np.std), ('min', np.min)]

    datagroup = dataframe.groupby(group_fields, sort=False)[out_fields]
    agg = datagroup.agg(aggregators)

    very_frequent = agg['count'] > agg['count'].quantile(quantile)
    very_summ = agg['sum'] > agg['sum'].quantile(quantile)
    very_big = agg['max'] > agg['max'].quantile(quantile)
    agg = agg[ very_frequent | very_summ | very_big ]

    agg.sort(['sum', 'max', 'count'], ascending=False, inplace=True)
    #agg = agg.groupby(level=0, group_keys=False).apply(lambda e: e.sort_index(by=['sum', 'max', 'count'], ascending=False).head(elements_per_group))

    return agg

def render_indices (dataframe, hashes):

    index_names = dataframe.index.names
    if index_names[0]:
        new_frame = dataframe.reset_index()
    else:
        new_frame = dataframe
        index_names = hashes.keys()

    to_map = set(index_names) & set(hashes.keys())
    for name in to_map:
        new_frame[name] = new_frame[name].map( lambda e: hashes[name](int(e)),
                                               na_action = 'ignore')

    if index_names[0]:
        return new_frame.set_index(index_names)
    else:
        return new_frame

