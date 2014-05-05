import re
import sys

from datetime import datetime, timedelta

import Utils
from Utils import (LogStatistician, current_utc_time_usecs,
                   decode_frontier, get_hostname,
                   find_file_offset_generic, datetime_to_UTC_epoch)

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

# A valid line has at least 3 characters in the servlet field
regex_line = re.compile(r'(?P<servlet>\S{4,}) (?P<timestamp>[0-9/]{8} [0-9.:]+ [A-Z]+ [+0-9]{5}) (?P<content>.*)')

class TomcatWatcher(LogStatistician):

    record_variables = {"servlet": str,
                        "version": str,
                        "query": str,
                        "who": str,
                        "error": str,
                        "sql": str,
                        "dbacq": str,
                        "state": str,
                        "fid": str,
                        "fwd": str,
                        "via": str,
                        "finish_mode": str,
                        "if_modified_since": str,
                        "other": str,
                        "cli_ver": str,
                        "pid": str,
                        "userid": str,
                        "userinfo": str,
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

    regex_general = regex_line
    regex_typical = re.compile(r'id=(?P<key>\S+) (?P<payload>.*)')
    regex_start = re.compile(r'servlet_version:(?P<version>\S+) start threads:(?P<threads_start>\d+) query (?P<query>\S+) raddr (?P<who>\S+) (?P<idinfo>.*)')
    regex_id_fields = re.compile(r"([^: ]+)(?:[:][ ])")
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
    regex_ims_mod = re.compile(r'modified at time: (?:(?:\S+ )*)')
    regex_ims_h = re.compile(r'using cached last-modified time of (?:(?:\S+ )*)')
    regex_ims_nc = re.compile(r'not modified (cached)')
    regex_ims_n = re.compile(r'not modified')
    regex_busy = re.compile(r'rejecting because servlet too busy')
    regex_init = re.compile(r'FrontierInit (?:(?:\S+ )*)')

    status_queued = 'queued'
    status_exec = 'executing'
    status_stop = 'finished'
    status_precom = 'precommitted'
    status_reject_busy = 'busy-rejected'

    finish_normal = 'ok'
    finish_timeout = 'timed-out'
    finish_error = 'aborted'

    IMS_mod = 'modified'
    IMS_not_mod = 'not modified'
    IMS_not_mod_cached = 'not modified (cached)'
    IMS_queried = 'queried'
    IMS_querying = 'querying'
    IMS_return = 'returned'
    IMS_cachehit = 'cache hit'

    ims_update = ( (regex_ims_h, IMS_cachehit),
                   (regex_ims_n, IMS_not_mod),
                   (regex_ims_nc, IMS_not_mod_cached),
                   (regex_ims_ret, IMS_return),
                   (regex_ims_q, IMS_queried),
                   (regex_ims_qng, IMS_querying),
                   (regex_ims_mod, IMS_mod), )

    id_fields_map = {'frontier-id': "fid",
                     'x-forwarded-for': "fwd",
                     'via': "via"}

    to_omit = ["don't know how to query timestamp for table dual",
               "DB connection released remaining=",
               "Reading file",
               "another thread found",
               "empty response, setting",
               "response committed, too late to query"]

    def __init__ (self, window_length_secs, use_timestamps_in_log=True):

        initial_rows_estimation = 100 * int(window_length_secs)
        LogStatistician.__init__( self, window_length_secs,
                                        initial_rows_estimation,
                                        use_timestamps_in_log )
        self._last_key = None

    def parse_log_line (self, line_in):

        line = line_in.strip()
        if not line: return

        general_match = self.regex_general.match(line)

        if general_match:
            record = general_match.groupdict()

            servlet = record['servlet']
            timestamp_log = record.pop('timestamp')
            if self.use_timestamps_in_log:
                timestamp = parse_utc_time_usecs (timestamp_log)
            else:
                timestamp = current_utc_time_usecs()
            self._last_timestamp = timestamp

            content = record.pop('content')
            content_match = self.regex_typical.match(content)

            if content_match:
                record = content_match.groupdict()

                record['servlet'] = servlet
                id_raw = record.pop('key').replace('-ka', '')
                key = servlet + id_raw

                payload = record.pop('payload')

                match = self.regex_start.match(payload)
                if match:
                    record.update (match.groupdict())
                    record['time_start'] = timestamp
                    record['threads_start'] = int(record['threads_start'])
                    record['state'] = self.status_queued
                    record['keepalives'] = 0
                    #record['who'] = get_hostname( record['who'])
                    record.update(self.process_id_info(record.pop('idinfo')))

                    self.data_D[key] = record
                    self.history_H.append (key)

                    self.newest_timestamp = timestamp
                    oldest_key = self.history_H[0]
                    self.oldest_timestamp = self.data_D.render_record (oldest_key, 'time_start')
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

                match = self.regex_busy.match(payload)
                if match:
                    update = {'state': self.status_reject_busy}
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
                    sys.stderr.write("%s %s\n" % (str(key), str(update)))
                    return

            else:
                key = servlet + '_-1'
                match = self.regex_init.match(content)
                if match:
                    if key not in self.data_D:
                        record['time_start'] = timestamp
                        record['finish_mode'] = self.finish_error
                        self.data_D[key] = record
                        self.history_H.append (key)
                    return

        else:

            if line.startswith('at '):
                if self._last_key:
                    key = self._last_key
                    timestamp = self._last_timestamp
                    self.finish_record (key, timestamp, self.finish_error)

            elif 'xception' in line:
                pass
            else:
                print "Unforeseen line:", line

            return

    def process_id_info (self, info_str):

        expected = set(('frontier-id', 'via', 'x-forwarded-for'))
        gotten = set(self.regex_id_fields.findall(info_str))
        valid = list( expected & gotten )

        str_indexes = [ info_str.index(fi) for fi in valid ]
        str_indexes, valid = zip(*sorted(zip(str_indexes, valid)))

        ini_indexes = [ str_indexes[ix] + len(field + ": ") for ix, field in enumerate(valid) ]
        end_indexes = list(str_indexes[1:])
        end_indexes.append(len(info_str))

        fields = {}
        for idx_field, name in enumerate(valid):
            start = ini_indexes[idx_field]
            end = end_indexes[idx_field]
            fields[name] = info_str[start:end].rstrip()

        if 'frontier-id' in fields:
            fid_fields = fields['frontier-id'].split(' ', 4)
            if len(fid_fields) == 5:
                client_id, client_ver, pid, uid, uinfo = fid_fields
                fields['frontier-id'] = client_id
                fields['cli_ver'] = client_ver
                fields['pid'] = pid
                fields['userid'] = uid
                fields['userinfo'] = uinfo

        for name in fields:
            if name in self.id_fields_map:
                datum = fields.pop(name)
                fields[self.id_fields_map[name]] = datum

        return fields

    def finish_record (self, key, timestamp, finish_mode):

        us_to_ms = 1e-3
        start_time = self.data_D.render_record( key, 'time_start')

        update = {'duration': (timestamp - start_time)*us_to_ms,
                  'state': self.status_stop,
                  'finish_mode': finish_mode}
        self.data_D.modify( key, update)

def parse_tomcat_timedate (timestamp_str):

    try:
        date_, time_, tz_name, tz_off = timestamp_str.split() #Ex: "09/07/13 00:01:32.208 CEST +0200"

        month, day, year = date_.split('/')
        hour, minute, f_secs = time_.split(':')

        ofs_sign, ofs_h, ofs_m = tz_off[0], int(tz_off[1:3]), int(tz_off[3:])

        if ofs_sign == '-':
            ofs_sign = 1
        else:
            ofs_sign = -1
        ofs_seconds = ofs_sign * 60 * (60*ofs_h + ofs_m)
        offset = timedelta(seconds=ofs_seconds)

        second, sec_float = f_secs.split('.')
        split_sec = float('0.' + sec_float)

        naive = datetime( 2000+int(year), int(month), int(day),
                         int(hour), int(minute), int(second),
                         int(1e6*split_sec) )

        return naive + offset

    except ValueError, ex:
        console.exception(">>> TS error:" + timestamp_str)
        return None

def parse_utc_time_secs (timestamp_str):

    timestamp = parse_tomcat_timedate( timestamp_str)
    epoch = datetime_to_UTC_epoch(timestamp)

    return epoch

def parse_utc_time_usecs (timestamp_str):

    timestamp = parse_tomcat_timedate( timestamp_str)
    epoch = datetime_to_UTC_epoch(timestamp)

    return int(1e6)*epoch + timestamp.microsecond

def get_timestamp (line):
    match = regex_line.match(line)
    if match:
        return match.group('timestamp')
    else:
        return None

get_first_timestamp = lambda file_name: Utils.get_first_timestamp(file_name, get_timestamp)
get_last_timestamp = lambda file_name: Utils.get_last_timestamp(file_name, get_timestamp)

def get_lines_between_timestamps (file_name, start_ts, end_ts):

    generate = False
    with open(file_name) as fd:
        for line in fd:

            if " start " in line:
                timestamp_str = ' '.join(line.split(' ', 6)[1:5])
                timestamp = parse_utc_time_usecs(timestamp_str)
                generate = (start_ts <= timestamp < end_ts)
                if timestamp >= end_ts:
                    break

            if generate:
                yield line

def get_valid_from_binary_offset (log_obj, offset_start):

    log_obj.seek(0, 2)
    file_size = log_obj.tell()

    log_obj.seek(offset_start, 0)

    timestamp = None
    last_offset = -1
    while not timestamp:
        offset = log_obj.tell()
        timestamp = get_timestamp(log_obj.readline())
        # It was necessary to use readline() instead of next(),
        #  as the offset reported by tell() was altered by
        #  Python's internal line buffering when using next()

        if last_offset == offset:
            raise ValueError("Stuck at byte %d (and file size is %d). Search stopped.\n" % (offset, file_size))
        last_offset = offset

    return parse_utc_time_secs(timestamp), offset

def find_log_offset (log_file, target_datetime, minutes_tol=1, hint_start=0):

    return find_file_offset_generic (get_valid_from_binary_offset, log_file,
                                     target_datetime, minutes_tol, hint_start)

class TomcatView(object):

    def __init__ (self, work_path, specifier, block_map_file, window_length_secs):

        self.blocks = BlockRecord(work_path, specifier, block_map_file)
        self.blocks.load()

        self.watch = TomcatWatcher(window_length_secs, True)

        self.window_length = timedelta(seconds=window_length_secs)
        self.start = None
        self.end = None

    def set_start (self, dt_start, move_end=True):

        if isinstance(dt_start, datetime):
            self.start = dt_start
        elif isinstance(dt_start, timedelta):
            self.start += dt_start

        if self.end and not move_end:
            self.window_length = self.end - self.start
        else:
            self.end = self.start + self.window_length
        self._update_spec()

    def set_end (self, dt_end, move_start=True):

        if isinstance(dt_end, datetime):
            self.end = dt_end
        elif isinstance(dt_end, timedelta):
            self.end += dt_end

        if self.start and not move_start:
            self.window_length = self.end - self.start
        else:
            self.start = self.end - self.window_length
        self._update_spec()

    def set_window (self, window_length_secs, move_start=True):
        if isinstance(window_length_secs, timedelta):
            self.window_length = window_length_secs
        else:
            self.window_length = timedelta(seconds=window_length_secs)
        if move_start:
            self.set_end(self.end)
        else:
            self.set_start(self.start)
        self._update_spec()

    def get_dataframe (self):

        return self.watch.as_dataframe()

    def load_data (self, machine):

        # For the time being
        self.watch.clear()

        oldest = self.watch.oldest_timestamp
        newest = self.watch.newest_timestamp

        if oldest is None or self._start_u < oldest:
            start_reading = self._start_u
        else:
            start_reading = oldest + 1

        if newest is None or self._end_u > newest:
            stop_reading = self._end_u
        else:
            stop_reading = newest + 1

        start_block = self.blocks.get_block(start_reading, machine)
        end_block = self.blocks.get_block(stop_reading, machine)
        for block in range(start_block, end_block+1):
            filename = self.blocks.get_file( block, machine)
            readline = get_lines_between_timestamps( filename, start_reading,
                                                               stop_reading )
            for line in readline:
                self.watch.parse_log_line(line)

        watch_length = self.watch.current_window_length_secs()
        remaining = watch_length - self.window_length.seconds
        self.watch.drop_oldest(remaining)

        return True

    def _update_spec (self):
        self._start_u = int( 1e6 * (self.start - epoch_origin).total_seconds() )
        self._end_u = int( 1e6 * (self.end - epoch_origin).total_seconds() )


def tomcat_aggregator (block_dataframe):

    tw_st = block_dataframe

    start = int( tw_st.time_start.min())
    end = int( tw_st.time_start.max())

    _s0 = tw_st.groupby(['servlet', 'state']).size().unstack()
    _s1 = tw_st.groupby(['servlet', 'finish_mode']).size().unstack()
    _s2 = tw_st.groupby('servlet').agg({'threads_start': ['min', 'max'],
                                        'threads_stop': ['min', 'max'],
                                        'size': ['min', 'max', 'sum'],
                                        'error': 'count',
                                        'duration': ['min', 'max', 'sum'],
                                        'msecs_acq': ['min', 'max', 'sum'],
                                        'msecs_finish': ['min', 'max', 'sum'],
                                        'msecs_stop': ['min', 'max', 'sum']})

    _s0.columns = ["{0}_{1}".format(_s0.columns.name, col) for col in _s0.columns.values]
    _s1.columns = ["{0}_{1}".format(_s1.columns.name, col) for col in _s1.columns.values]
    _s2.columns = map(str.strip, map('_'.join, _s2.columns.values))

    df = _s0.join([_s1, _s2])
    df['time_start'] = start
    df['time_end'] = end
    df['span'] = (end - start)/1e6

    return df.reset_index()

def render_queries (dataframe):

    dataframe['query'] = dataframe['query'].apply(decode_frontier)
    dataframe['who'] = dataframe['who'].apply(get_hostname)
    dataframe['forward'] = dataframe['forward'].apply(lambda s: ','.join([get_hostname(ip) for ip in s.strip().split(',')]))

    return dataframe

