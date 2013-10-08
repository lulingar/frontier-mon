import base64
import copy
import collections
import functools
import json
import numpy as np
import numpy.ma as ma
import os
import socket
import sys
import time
import zlib

from datetime import datetime
from heapq import nsmallest
from operator import itemgetter
from string import maketrans

def current_utc_time_usecs():
    return int (1e6 * time.time())

def parse_utc_time_usecs (timestamp):
    secs = float( datetime.strptime( timestamp, "%m/%d/%y %H:%M:%S.%f").strftime('%s.%f'))
    return int( 1e6 * secs )

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
        self.ilist = []
        self.odict = {}
        self._reusable_indices = set()

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

        self.column_table = IndexDict()
        self.hash_table = {}
        self.index_table = IndexDict()
        self.data_table = ma.masked_all( (initial_rows, len(variables)),
                                         dtype = self._data_type )

        for name, vartype in variables.items():
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
        self.data_table[index,:] = ma.masked

    def clear (self):
        self.index_table.clear()
        self.data_table.fill(ma.masked)

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


# Testing code
if __name__ == "__main__":

    import random
    import threading

    object_bag = ["algo", "bueeenas", "dksdjiw", "dykstra", "agent", "test"]
    watch = TimeWindowedRecord (4)

    def feed_events (signal):
        while not signal.is_set():
            signal.wait( random.gauss(1, 1) )
            print "<feed!>"
            watch.event( random.choice(object_bag))

    def show_window (signal):
        while not signal.is_set():
            signal.wait(2)
            now = time.strftime("%H:%M:%S", time.gmtime())
            try:
                pairs = [ "%s (%.3f)" % (x[1], x[0]/1e6) for x in watch.history_H ]
                print now, watch.interval_sum_L/1e6, pairs
            except KeyError:
                print watch.history_H
                print watch.object_table_T

    threads_signal = threading.Event()
    t_f = threading.Thread (target=feed_events, name='feed', args=(threads_signal,))
    t_s = threading.Thread (target=show_window, name='show', args=(threads_signal,))

    t_f.start()
    t_s.start()
    try:
        while True: time.sleep(100)
    except (KeyboardInterrupt, SystemExit):
        print "Exitting...",
        threads_signal.set()
        t_f.join()
        t_s.join()
        print "success!"

