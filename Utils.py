import base64
import bisect
import calendar
import copy
import collections
import functools
import gzip
import itertools
import json
import operator
import os
import socket
import sys
import time
import zlib

import dateutil as du
import dateutil.parser as du_parser
import numpy as np
import numpy.ma as ma
import pandas as pd
pd.options.display.max_columns = 40

from glob import glob
from heapq import nsmallest
from operator import itemgetter
from string import maketrans
from datetime import datetime, timedelta

from tacit import tac

def current_utc_time_usecs():
    return int (1e6 * time.time())

def lru_cache (maxsize=128):
    '''Least-recently-used cache decorator.

    Arguments to the cached function must be hashable.
    Cache performance statistics stored in f.hits and f.misses.
    http://en.wikipedia.org/wiki/Cache_algorithms#Least_Recently_Used

    '''
    def decorating_function (user_function):
        cache = collections.OrderedDict()    # order: least recent to most recent

        @functools.wraps(user_function)
        def wrapper(*args, **kwds):
            key = args
            if kwds:
                key += tuple(sorted(kwds.items()))
            try:
                result = cache.pop(key)
                wrapper.hits += 1

            except KeyError:
                result = user_function(*args, **kwds)
                wrapper.misses += 1
                if len(cache) >= maxsize:
                    cache.popitem(0)    # purge least recently used cache entry

            cache[key] = result         # record recent use of this key
            return result

        wrapper.hits = wrapper.misses = 0
        return wrapper

    return decorating_function

def lfu_cache (maxsize=128):
    '''Least-frequenty-used cache decorator.

    Arguments to the cached function must be hashable.
    Cache performance statistics stored in f.hits and f.misses.
    Clear the cache with f.clear().
    http://en.wikipedia.org/wiki/Least_Frequently_Used

    '''
    def decorating_function (user_function):
        cache = {}                        # mapping of args to results
        use_count = collections.Counter() # times each key has been accessed
        kwarg_mark = object()             # separate positional and keyword args

        @functools.wraps(user_function)
        def wrapper (*args, **kwargs):
            key = args
            if kwargs:
                key += (kwarg_mark,) + tuple(sorted(kwargs.items()))

            # get cache entry or compute if not found
            try:
                result = cache[key]
                use_count[key] += 1
                wrapper.hits += 1

            except KeyError:
                # need to add something to the cache, make room if necessary
                if len(cache) == maxsize:
                    for k, _ in nsmallest(maxsize // 10 or 1,
                                            use_count.iteritems(),
                                            key=itemgetter(1)):
                        del cache[k], use_count[k]
                result = user_function(*args, **kwargs)
                cache[key] = result
                use_count[key] += 1
                wrapper.misses += 1

            return result

        def clear():
            cache.clear()
            use_count.clear()
            wrapper.hits = wrapper.misses = 0

        wrapper.hits = wrapper.misses = 0
        wrapper.clear = clear
        wrapper.cache = cache
        return wrapper

    return decorating_function

class TimeWindowedRecord(object):

    def __init__ (self, window_length_secs, now=None):

        self.window_length_V = int (window_length_secs*1e6)
        self.history_H = collections.deque()
        self.interval_sum_L = 0

        self.access_counter = collections.Counter()

        if not now:
            now = current_utc_time_usecs()
        self.last_time = now

    def event (self, in_object, now=None):

        if not now:
            now = current_utc_time_usecs()
        interval = now - self.last_time
        self.last_time = now

        event = [interval, in_object]
        self.access_counter[in_object] += 1

        self.interval_sum_L += interval

        while self.interval_sum_L > self.window_length_V and self.history_H:
            interval_out, object_out = self.history_H.popleft()
            self.interval_sum_L -= interval_out
            self.access_counter[object_out] -= 1

        self.history_H.append (event)

    def current_window_length_secs (self):
        return self.interval_sum_L*1e-6

    def most_frequent (self, ranks):
        return self.access_counter.most_common (ranks)

    def serialize (self):
        return json.dumps ({'window': self.window_length_V,
                           'history': list(self.history_H)})

class LogStatistician(object):

    def __init__ (self, window_length_secs, initial_rows_estimate, use_timestamps_in_log):

        self.use_timestamps_in_log = use_timestamps_in_log

        self.window_length_V = int( 1e6 * window_length_secs)
        self.oldest_timestamp = None
        self.newest_timestamp = None

        self.history_H = collections.deque()
        self.data_D = RecordTable( self.record_variables,
                                   initial_rows = initial_rows_estimate,
                                   datatype = int )
        self._last_timestamp = None

    def parse_log_line (self, line_in):
        raise NotImplementedError()

    def drop_oldest (self, timelapse, unit=1e6):

        if timelapse > 0:
            current_timespan_usecs = self.newest_timestamp - self.oldest_timestamp
            while current_timespan_usecs > timelapse * unit:
                dropped_key = self.history_H.popleft()
                self.oldest_timestamp = self.data_D.render_record (dropped_key, 'time_start')
                del self.data_D[dropped_key]
                current_timespan_usecs = self.newest_timestamp - self.oldest_timestamp

    def update (self):
        self.drop_oldest(self.window_length_V, unit=1)

    def advance_records (self, line_in):

        self.parse_log_line(line_in)
        self.update()

    def clear (self):

        self.data_D.clear(full=False)
        self.history_H.clear()
        self.oldest_timestamp = None
        self.newest_timestamp = None
        self._last_timestamp = None

    def current_window_length_secs (self):

        if self.newest_timestamp and self.oldest_timestamp:
            current_timespan_usecs = self.newest_timestamp - self.oldest_timestamp
            return current_timespan_usecs * 1e-6
        else:
            return -1

    def as_dataframe (self):

        df = pd.DataFrame( self.data_D.get_raw_values(),
                           columns = list(self.data_D.column_table) )

        for col, mapping in self.data_D.hash_table.iteritems():
            df[col] = df[col].map( lambda e: mapping(int(e)),
                                   na_action = 'ignore')
        return df

    def __len__(self):
        return len(self.history_H)

@lfu_cache(maxsize=1024)
def get_hostname (ip):

    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

@lfu_cache(maxsize=1024)
def decode_frontier (query):

    char_translation = maketrans(".-_", "+/=")
    url_parts = query.split ("encoding=BLOB")

    if len(url_parts) > 1:

        url = url_parts[1].split("&p1=", 1)
        encparts = url[1].split("&", 1)
        if len(encparts) > 1:
            ttlpart = "&" + encparts[1]
        else:
            ttlpart = ""
        encoded_query = encparts[0].translate(char_translation)
        try:
            decoded_query = zlib.decompress (base64.binascii.a2b_base64 (encoded_query)).strip()
        except zlib.error:
            decoded_query = encoded_query
    else:
        decoded_query = query

    return decoded_query


class IndexDict(object):

    def __init__ (self, iterable=None):

        if iterable:
            self.odict = dict([(elem, i) for i, elem in enumerate(iterable)])
            self.ilist = list(iterable)
        else:
            self.odict = {}
            self.ilist = []

        self._reusable_indices = set()

    def add (self, item):
        if not self._reusable_indices:
            index = len(self.ilist)
        else:
            index = min(self._reusable_indices)
            self._reusable_indices.remove(index)

        self.odict[item] = index

        if len(self.ilist) > index:
            self.ilist[index] = item
        else:
            self.ilist.append(item)
        return index

    def remove (self, item):
        if item not in self.odict:
            raise KeyError("%s is not in the dictionary" % str(item))
        index = self.odict[item]
        self.remove_by_index(index)

    def remove_by_index (self, index):

        if index >= len(self.ilist) or index < 0:
            raise IndexError("Index out of range (%d)" % index)

        self._reusable_indices.add(index)
        item = self.ilist[index]
        self.ilist[index] = None
        del self.odict[item]

    def clear (self):
        del self.ilist[:]
        self.odict.clear()
        self._reusable_indices.clear()

    def __getitem__(self, item):
        if item in self.odict:
            return self.odict[item]
        else:
            return self.add(item)

    def __setitem__(self, item, value):
        # The rvalue "value" is silently ignored
        self.add(item)

    def __delitem__(self, item):
        self.remove(item)

    def __contains__(self, item):
        return item in self.odict

    def __len__(self):
        return len(self.odict)

    def __iter__(self):
        return iter(self.ilist)

    def iteritems(self):
        return self.odict.iteritems()

    def itervalues(self):
        return self.odict.itervalues()

    def values(self):
        return sorted(self.odict.itervalues())

    def __repr__ (self):
        elems = sorted (self.odict.iteritems(), key = lambda k: k[1])
        elem_str = ', '.join(["%d:%s" % (i, repr(e)) for e, i in elems])
        return "%s{%s}" % (self.__class__.__name__, elem_str)

    def __call__(self, index):
        if index >= len(self.ilist):
            raise IndexError("Index %d out of range (%d)" % (index,
                                                             len(self.ilist)))
        return self.ilist[index]


class RecordTable(object):

    def __init__ (self, variables, initial_rows=128, datatype=np.float64):

        if not isinstance(variables, dict):
            raise KeyError("Variables must be a dictionary of names-types pairs")

        self._data_type = datatype
        self._data_table_growth_factor = 0.3
        self._variables = variables

        self.column_table = IndexDict()
        self.hash_table = {}
        self.index_table = IndexDict()
        self.data_table = ma.masked_all( (initial_rows, len(variables)),
                                         dtype = self._data_type )
        self._populate_indices()

    def _populate_indices (self):

        for name, vartype in self._variables.items():
            self.column_table.add (name)
            if vartype not in (int, long, float):
                self.hash_table[name] = IndexDict()

    def get_row_variable (self, index, variable):

        var_index = self.column_table[variable]

        if variable in self.hash_table:
            hash_index = self.data_table[index, var_index]
            if ma.is_masked(hash_index):
                value = None
            else:
                value = self.hash_table[variable](int(hash_index))
        else:
            value = self.data_table[index, var_index]

        return value

    def render_record (self, key, field=None):

        if key not in self.index_table:
            raise KeyError("key %s does not exist in table" % str(key))

        index = self.index_table[key]
        get_val = self.get_row_variable
        if field:
            return get_val (index, field)

        else:
            record = {'key': key}
            for name in self.column_table:
                value = get_val (index, name)
                if value: record[name] = value
            return record

    def get_raw_values (self):
        return self.data_table[self.index_table.values(), :]

    def insert (self, key, record):

        if key in self.index_table:
            raise KeyError("key %s already exists in table" % str(key))

        added_row_index = self.index_table[key]

        num_current_rows = len(self.index_table)
        if num_current_rows >= self.data_table.shape[0]:
            num_new_rows = int(self._data_table_growth_factor * num_current_rows)
            new_rows = ma.masked_all( (num_new_rows, len(self.column_table)),
                                      dtype = self._data_type )
            self.data_table = ma.vstack ((self.data_table, new_rows))
            print "Table enlarged to %d rows" % self.data_table.shape[0]

        for key, in_value in record.items():

            if key not in self.column_table:
                raise KeyError('Variable "%s" is not registered as a table column' % str(key))
            if key in self.hash_table:
                value = self.hash_table[key][in_value]
            else:
                value = in_value

            index = self.column_table[key]
            self.data_table[added_row_index, index] = value

    def modify (self, key, updates):

        if key not in self.index_table:
            raise KeyError("key %s does not exist in table" % str(key))

        index = self.index_table[key]

        for name, in_value in updates.items():
            var_index = self.column_table[name]

            if name in self.hash_table:
                value = self.hash_table[name][in_value]
            else:
                value = in_value

            self.data_table[index, var_index] = value

    def remove (self, key):

        assert key in self.index_table, "key %s does not exist in table" % str(key)
        index = self.index_table[key]
        self.index_table.remove_by_index(index)

        # Numpy >= 1.8 prevents assignment of ma.masked (whose dtype=float)
        #  to a masked array of a different dtype
        #self.data_table[index,:] = ma.masked

    def clear (self, full=False):

        # Numpy >= 1.8 prevents assignment of ma.masked (whose dtype=float)
        #  to a masked array of a different dtype
        #self.data_table.fill(ma.masked)

        self.index_table.clear()
        if full:
            self.column_table.clear()
            self.hash_table.clear()
            self._populate_indices()

    def pop (self, key):

        record = self.render_record(key)
        self.remove(key)
        return record

    def __delitem__(self, key):
        self.remove(key)

    def __setitem__(self, key, record):
        self.insert (key, record)

    def __call__(self, index):
        if index >= len(self.index_table):
            raise IndexError("This table currently has only %d rows" % len(self.index_table))
        key = self.index_table(index)
        return self.render_record(key)

    def __contains__(self, key):
        return key in self.index_table

    def __len__(self):
        return len(self.index_table)

    def __getitem__(self, key):
        return self.render_record(key)

    #def __repr__(self):
    #TODO: Pretty-print current table records


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

def get_last_n_lines (filename, n=1):
    i = 0
    lines = []
    for line in tac(filename):
        lines.append(line)
        i +=1
        if i == n: break
    return ''.join(lines)

def save_object (save_file, dictionary):
    with open(save_file, 'w') as fd:
        json.dump(dictionary, fd)

def is_strictly_increasing(lst):
    op = operator.lt
    return all(op(x, y) for x, y in itertools.izip(lst, lst[1:]))

def get_first_timestamp (file_name, timestamp_fcn):
    for line in open(file_name):
        ts = timestamp_fcn(line)
        if ts:
            return ts

def get_last_timestamp (file_name, timestamp_fcn):
    for line in tac(file_name):
        ts = timestamp_fcn(line)
        if ts:
            return ts

def iternamedtuples (dataframe):
    Row = collections.namedtuple('Row', dataframe.columns)
    for row in dataframe.itertuples():
        yield Row(*row[1:])

def gather_stats (machine, time_span, watch, log_file,
                  processing_f, ts_getter, ts_parser, ts_locator,
                  max_in_core=400e3):

    def close_bin (chunks, watch, block_start, processing_f):

        chunks.append(watch.as_dataframe())
        aggregation = processing_f( pd.concat( chunks))
        aggregation['block_start'] = block_start
        pickled = list( iternamedtuples( aggregation))

        return pickled

    start, end, time_bin = time_span
    time_bin_secs = time_bin.total_seconds()

    dframes = []
    chunks = []
    first_chunk = True
    new_bin = False
    previous_line_index = LagFactory(0)
    watch.clear()

    log_size = os.path.getsize(log_file)
    _, start_offset = ts_locator(log_file, start, minutes_tol=0.5)

    with open(log_file) as log:

        log.seek(start_offset, 0)

        for line in log:
            previous_line_index(log.tell())

            if ts_getter(line):
                ts = ts_parser( ts_getter(line))
                if ts < start:
                    continue
                if ts > end:
                    break
            else:
                if first_chunk:
                    continue

            if first_chunk:
                first_chunk = False
                new_bin = True

            if new_bin:
                block_start = previous_line_index()
                new_bin = False

            try:
                watch.parse_log_line(line)
            except KeyError:
                chunks.append(watch.as_dataframe())
                watch.clear()
                watch.parse_log_line(line)

            collected_time = watch.current_window_length_secs()
            in_core = len(watch)
            if collected_time > time_bin_secs or in_core > max_in_core:

                progress = (ts - start).total_seconds() / (end - start).total_seconds()
                print "{0}: +{1:f} secs. ({2:.2f} %)".format(machine, collected_time, 100*progress)
                dframes.append( close_bin( chunks, watch, block_start, processing_f))
                new_bin = True
                watch.clear()
                del chunks[:]

    if not first_chunk:
        dframes.append( close_bin( chunks, watch, block_start, processing_f))

    if dframes:
        assembly = pd.concat( (pd.DataFrame(frame, columns=frame[0]._fields) for frame in dframes),
                              axis=0, ignore_index=True, verify_integrity=False )
        return assembly

    return None

def aggregator (dict_of_frames, column_name):

    agp = pd.Panel(dict_of_frames)
    agl = agp.transpose(items='minor', major='major', minor='items')\
             .to_frame(filter_observations=False)\
             .reset_index(level=1)
    agl.rename( columns={'minor': column_name}, inplace=True)
    agl.index.names = ['']

    return agl

def resampled_pivot (dataframe, index, column, values, resample_spec, resample_how):

    indexed = dataframe.set_index([index])
    column_values = dataframe[column].unique()
    dataframe_cols = {}

    for col_value in column_values:

        filtered = indexed[ indexed[column] == col_value ]
        series = filtered[values]
        series = series.resample (resample_spec, how=resample_how)
        dataframe_cols[col_value] = series

    return pd.DataFrame(dataframe_cols).fillna(0)

def get_log_blocks (specifier, work_path, machine):

    base_path = work_path + '{0:d}/{1}'
    log_file = base_path.format( machine, path_specifier)
    block_table = base_path.format( machine, path_specifier) + ".assembly.csv"
    table = pd.read_csv(block_table)

    return (table, log_file)

def data_time_slice (table, log_file, watch, start_time, end_time):

    idx = bisect.bisect(table.index, start_time) - 1
    block_start = table.iloc[idx]['block_start']
    idx = bisect.bisect(table.index, end_time)
    block_end = table.iloc[idx]['block_start']

    chunks = []

    with open(log_file) as log:
        log.seek(block_start, 0)

        for line in log:
            if log.tell() >= block_end:
                break

            try:
                watch.parse_log_line(line)
            except KeyError:
                chunks.append(watch.as_dataframe())
                watch.clear()
                watch.parse_log_line(line)

    chunks.append(watch.as_dataframe())
    assembly = pd.concat( chunks, ignore_index=True )

    return assembly

def simple_datetime_entry (datetime_str):

    local_zone = du.tz.tzlocal()
    dto = du_parser.parse(datetime_str)

    if dto.tzinfo is None:
        dto = dto.replace(tzinfo=local_zone)

    return dto.astimezone(local_zone)

def mark_failover (df, host_ip_field, geo):

    localhost_addr = '127.0.0.1'

    df['IsSquid'] = df[host_ip_field].isin(geo['Ip'])
    df['IsDirect'] = False
    df['ThroughSquids'] = False
    df['Origin'] = ''

    squids = set(geo.Ip.values.tolist())
    squids.discard(localhost_addr)

    mark = lambda entry: mark_failover_from_fwd(entry, squids)
    local = ( df[host_ip_field] == localhost_addr )

    df['IsDirect'][local], df['ThroughSquids'][local], df['Origin'][local] = zip(*df['fwd'][local].map(mark))

    df['Origin'][~local] = df[host_ip_field][~local]
    df['IsDirect'][~local] = True
    df['ThroughSquids'][~local] = df[host_ip_field][~local].isin(geo['Ip'])

def mark_failover_from_fwd (ip_list, squid_set):

    ips = ip_list.split(', ')
    index = range(len(ips))

    is_squid = [ ip in squid_set for ip in ips ]
    through_squids = any(is_squid)
    is_direct = (len(ips) == 1)

    if len(ips) > 1:
        origin_path = [ ips[idx] for idx in index if not is_squid[idx] ]
        origin_path.extend( ips[idx] for idx in index if is_squid[idx] )
    else:
        origin_path = ips

    return is_direct, through_squids, origin_path[0]

def find_file_offset_generic (find_valid_offset_function, log_file, target_datetime, minutes_tol=1, hint_start=0):

    # target_datetime is naive, interpreted here as UTC
    assert isinstance(target_datetime, datetime) or\
           isinstance(target_datetime, int)

    log = open(log_file, 'rb')

    start = hint_start
    log.seek(0, 2)
    end = log.tell()

    if isinstance(target_datetime, datetime):
        target_epoch = datetime_to_UTC_epoch(target_datetime)
    else:
        target_epoch = target_datetime

    # Designed for logs that record 24 hours of activity
    tolerance = 60.0 * minutes_tol
    iterations_left = int(np.ceil(np.log2(24*3600/tolerance)))

    valid_found = False
    while not valid_found and iterations_left:

        pointer = (start + end)/2
        timestamp_epoch, offset = find_valid_offset_function(log, pointer)
        error = target_epoch - timestamp_epoch

        valid_found = ( abs(error) <= tolerance )
        if error < 0:
            end = offset
        else:
            start = offset

        iterations_left -= 1

    log.close()

    if valid_found:
        return timestamp_epoch, offset
    else:
        return -1, -1

def datetime_to_UTC_epoch (dt):

    return calendar.timegm( dt.utctimetuple())

class LagFactory(object):

    def __init__ (self, start=0):

        self._store = start

    def __call__ (self, value=None):

        lag = self._store
        if value:
            self._store = value

        return lag

