import bisect
import json
import random
import re

import dateutil as du

from datetime import datetime, timedelta
from glob import glob

import Utils
from Utils import (LogStatistician, current_utc_time_secs,
                   decode_frontier, get_hostname,
                   find_file_offset_generic, datetime_to_UTC_epoch)

series = {0: "UDP?",
          1: "Info",
          2: "Successful",
          3: "Redirection",
          4: "Client_Error",
          5: "Server_Error",
          6: "Broken_Server_Software"}

codes = {100: "Continue",
         101: "Switching Protocols",
         102: "Processing",
         200: "OK",
         201: "Created",
         202: "Accepted",
         203: "Non-Authoritative Information",
         204: "No Content",
         205: "Reset Content",
         206: "Partial Content",
         207: "Multi Status",
         300: "Multiple Choices",
         301: "Moved Permanently",
         302: "Moved Temporarily",
         303: "See Other",
         304: "Not Modified",
         305: "Use Proxy",
         307: "Temporary Redirect",
         400: "Bad Request",
         401: "Unauthorized",
         402: "Payment Required",
         403: "Forbidden",
         404: "Not Found",
         405: "Method Not Allowed",
         406: "Not Acceptable",
         407: "Proxy Authentication Required",
         408: "Request Timeout",
         409: "Conflict",
         410: "Gone",
         411: "Length Required",
         412: "Precondition Failed",
         413: "Request Entity Too Large",
         414: "Request URI Too Large",
         415: "Unsupported Media Type",
         416: "Request Range Not Satisfiable",
         417: "Expectation Failed",
         422: "Unprocessable Entity",
         424: "Locked",
         424: "Failed Dependency",
         433: "Unprocessable Entity",
         500: "Internal Server Error",
         501: "Not Implemented",
         502: "Bad Gateway",
         503: "Service Unavailable",
         504: "Gateway Timeout",
         505: "HTTP Version Not Supported",
         507: "Insufficient Storage",
         600: "Squid: header parsing error",
         601: "Squid: header size overflow detected while parsing",
         601: "roundcube: software configuration error",
         603: "roundcube: invalid authorization"}

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
squid_access_re = re.compile(r"""^(?P<who>\S+) (?P<user_ident>\S+) (?P<user_name>\S+) \[(?P<timestamp>\S+ \S+)\] "(?P<method>\S+) (?P<url>\S+) HTTP/(?P<proto_version>\S+)" (?P<http_code>\d+) (?P<size>\d+) (?P<req_status>[^: ]+):(?P<hierarchy_status>\S+) (?P<duration>\d+) "(?P<frontier_id>[^"]+)" "(?P<IMS>[^"]*)"$""")
squid_url_re = re.compile(r'[^/]+[/]+(?P<server>[^/:]+)[:]*[^/]*/(?P<data>\S+)')
squid_data_re = re.compile(r'(?P<servlet>[^/]+)/(?P<query_name>[^/]+)[/?](?P<query>\S+)')
class SquidWatcher(LogStatistician):

    record_variables = {'if-modified-since': str,
                        'who': str,
                        'fid_sw_release': str,
                        'fid_sw_version': str,
                        'fid_uid': str,
                        'fid_userdn': str,
                        'hierarchy_status': str,
                        'method': str,
                        'proto_version': str,
                        'query': str,
                        'query_name': str,
                        'req_status': str,
                        'server': str,
                        'servlet': str,
                        'user_ident': str,
                        'user_name': str,
                        'http_code': int,
                        'fid_pid': int,
                        'duration': int,
                        'size': int,
                        'timestamp':int}

    def __init__ (self, window_length_secs, use_timestamps_in_log=True):

        initial_rows_estimation = 100 * int(window_length_secs)
        LogStatistician.__init__( self, window_length_secs,
                                        initial_rows_estimation,
                                        use_timestamps_in_log )

    def parse_log_line  (self, line_in):

        line = line_in.strip()
        if not line: return

        while True:
            key = random.randint(0, 2**32)
            if key not in self.data_D: break

        record = parse_log_line(line, self.use_timestamps_in_log)

        if record:
            timestamp = record['timestamp']
            self._last_timestamp = timestamp

            self.data_D[key] = record
            self.history_H.append (key)

            self.newest_timestamp = timestamp
            oldest_key = self.history_H[0]
            self.oldest_timestamp = self.data_D.render_record (oldest_key, 'timestamp')

        return


def parse_log_line (line, use_timestamps_in_log=True):

    match = squid_access_re.match(line)

    if match:
        record = match.groupdict()

        timestamp_log = record.pop('timestamp')
        if use_timestamps_in_log:
            timestamp = parse_utc_time_secs( timestamp_log)
        else:
            timestamp = current_utc_time_secs()
        record['timestamp'] = timestamp
        record['if-modified-since'] = record.pop('IMS')

        frontier_id = record.pop('frontier_id')

        if 'opportunistic probe' in frontier_id:
            record['fid_sw_release'] = frontier_id
        else:
            frontier_id_parts = frontier_id.split()

            if len(frontier_id_parts) > 1:
                record['fid_sw_release'] = frontier_id_parts[0]
                record['fid_sw_version'] = frontier_id_parts[1]

                if len(frontier_id_parts) > 2:
                    if frontier_id_parts[0] != "SLS_probe":
                        record['fid_pid'] = frontier_id_parts[2]
                if len(frontier_id_parts) > 3:
                    record['fid_uid'] = frontier_id_parts[3]
                    record['fid_userdn'] = ' '.join(frontier_id_parts[4:])
            else:
                record['fid_sw_release'] = frontier_id_parts[0]

        #record['who'] = get_hostname( record['who'])

        url = record.pop('url')
        url_match = squid_url_re.match(url)
        if url_match:
            record.update( url_match.groupdict())
            data = record.pop('data')

            data_match = squid_data_re.match(data)
            if data_match:
                record.update(data_match.groupdict())
                #record['query'] = decode_frontier( record['query'])
                return record
        else:
            data = '_empty_'

        record['query'] = data
        record['query_name'] = "_primitive_"
        return record

    print "No record",line
    return None

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
        second = int(td[18:20])

        ofs_sign, ofs_h, ofs_m = tz[0], int(tz[1:3]), int(tz[3:])

        if ofs_sign == '-':
            ofs_sign = 1
        else:
            ofs_sign = -1
        ofs_seconds = ofs_sign * 60 * (60*ofs_h + ofs_m)
        offset = timedelta(seconds=ofs_seconds)

        naive = datetime(year, month, day, hour, minute, second)

        return naive + offset

    except ValueError:
        print ">>> TS error:", timestamp_str
        return None

def parse_utc_time_secs (timestamp_str):

    timestamp = parse_squid_timedate( timestamp_str)
    epoch = datetime_to_UTC_epoch(timestamp)

    return epoch

def get_timestamp (line):
    return line.split('[',1)[1].split(']',1)[0]

get_first_timestamp = lambda file_name: Utils.get_first_timestamp(file_name, get_timestamp)
get_last_timestamp = lambda file_name: Utils.get_last_timestamp(file_name, get_timestamp)

def get_timestamp_tables (base_path):
    tables_first_str = {}
    tables_last_str = {}
    for machine in (1, 2, 3):
        tables_first_str[machine] = {}
        tables_last_str[machine] = {}
        blocks = glob( base_path.format( machine) + '*')
        for block in blocks:
            tables_first_str[machine][block] = get_first_timestamp(block)
            tables_last_str[machine][block] = get_last_timestamp(block)

    return tables_first_str, tables_last_str

def get_lines_between_timestamps (file_name, start_ts, end_ts):

    generate = False
    with open(file_name) as fd:
        for line in fd:

            timestamp_str = line.split('[',1)[1].split(']',1)[0]
            timestamp = parse_utc_time_secs(timestamp_str)
            generate = (start_ts <= timestamp < end_ts)
            if timestamp >= end_ts:
                break

            if generate:
                yield line

def find_log_offset (log_file, target_datetime, minutes_tol=1, hint_start=0):

    return find_file_offset_generic (get_valid_from_binary_offset, log_file,
                                     target_datetime, minutes_tol, hint_start)

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

class BlockRecord(object):

    def __init__ (self, work_path, specifier, savefile):

        self.base_path = work_path + '{0:d}/' + specifier + '/'
        self.block_path = self.base_path + '{1:03d}'
        self.save_file = savefile

    def load (self):

        with open(self.save_file) as fd:
            timestamps_lib = json.load(fd)

        tables_first = {}
        for machine, table in timestamps_lib.items():
            first = sorted(table.values())
            tables_first[int(machine)] = map(parse_squid_timedate, first)

        self.tables = tables_first

    def get_block (self, timestamp, machine):

        table = self.tables[machine]

        if isinstance(timestamp, str):
            _ts = parse_squid_timedate(timestamp)
        elif isinstance(timestamp, datetime):
            _ts = timestamp
        elif isinstance(timestamp, int):
            _ts = datetime.fromtimestamp(timestamp*1e-6, du.tz.tzutc())

        idx = bisect.bisect(table, _ts) - 1
        if 0 <= idx < len(table):
            return idx

        raise ValueError

    def get_file (self, block, machine):

        if 0 <= block < len(self.tables[machine]):
            return self.block_path.format(machine, block)
        raise IndexError

class SquidView(object):

    def __init__ (self, work_path, specifier, block_map_file, window_length_secs):

        self.blocks = BlockRecord(work_path, specifier, block_map_file)
        self.blocks.load()

        self.watch = SquidWatcher(window_length_secs, True)

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
            if not readline:
                return False

            for line in readline:
                self.watch.parse_log_line(line)

        watch_length = self.watch.current_window_length_secs()
        remaining = watch_length - self.window_length.seconds
        self.watch.drop_oldest(remaining)

        return True

    def _update_spec (self):
        self._start_u = int( 1e6 * (self.start - epoch_origin).total_seconds() )
        self._end_u = int( 1e6 * (self.end - epoch_origin).total_seconds() )

def squid_aggregator (block_dataframe):

    sq_st = block_dataframe

    start = int( sq_st.timestamp.min())
    end = int( sq_st.timestamp.max())

    sq_st.http_code /= 100
    sq_st.http_code = sq_st.http_code.map(series)
    _s0 = sq_st.groupby(['servlet', 'http_code']).size().unstack()
    _s1 = sq_st.groupby('servlet').agg({'size': ['min', 'max', 'sum'],
                                        'duration': ['min', 'max', 'sum']})
    _s2 = sq_st.groupby(['servlet', 'req_status']).size().unstack()

    _s0.columns = ["{0}_{1}".format(_s0.columns.name, col) for col in _s0.columns.values]
    _s1.columns = map(str.strip, map('_'.join, _s1.columns.values))
    _s2.columns = ["{0}_{1}".format(_s2.columns.name, col) for col in _s2.columns.values]

    df = _s0.join([_s1, _s2])
    df['time_start'] = start
    df['time_end'] = end
    df['span'] = (end - start)/1e6

    return df.reset_index()

def render_queries (dataframe):

    dataframe['query'] = dataframe['query'].apply(decode_frontier)
    dataframe['who'] = dataframe['who'].apply(get_hostname)

    return dataframe

