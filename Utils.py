import collections
import functools
import json
import re
import sys
import time

from heapq import nsmallest
from operator import itemgetter

def current_utc_time_usecs():
    return int (1e6 * time.time())

def parse_utc_time_usecs (timestamp):
    usecs = int (1e6 * time.mktime (time.strptime (timestamp, "%m/%d/%y %H:%M:%S.%f")))
    return usecs

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
    
        self.stats_list = (
                {'filter': {'servlet':"FrontierProd"},
                 'interest': 'query',
                 'weighter': 'who',
                 'action': 'tally'},
                {'filter': {'servlet':"FrontierProd"},
                 'interest': 'who',
                 'weighter': 'size',
                 'action': 'sum'},
                {'filter': {'servlet':"smallfiles"},
                 'interest': 'who',
                 'weighter': 'size',
                 'action': 'sum'}
                )
        self.statistics = RecordStatistics(self.stats_list)

    def parse_log_line (self, line_in):

        line = line_in.strip()
        if not line: return

        general_match = self.regex_general.match(line)

        if general_match:
            
            record = general_match.groupdict()
            id_raw = record.pop('id')
            id = int (id_raw.replace('-ka', ''))

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

                record.update (match.groupdict())
                record['time_start'] = timestamp 
                record['state'] = self.status_queued 
                record['keepalives'] = 0

                complement = record.pop('complement')
                parts = complement.split(':')
                record['fid'] = parts[0].replace(' x-forwarded-for', '').replace(' via', '')
                if len(parts) > 1:
                    if parts[-2].endswith(' x-forwarded-for'):
                        record['forward'] = parts[-1]
                    record['via'] = ':'.join(parts[1:-1]).replace('x-forwarded-for', '')

                record['threads_start'] = int(record['threads_start'])
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
                record['active_acq'] = int(record['active_acq'])
                record['msecs_acq'] = int(record['msecs_acq'])
                return
            
            match = self.regex_dbfin.match(payload)
            if match:
                record.update (match.groupdict())
                record['msecs_finish'] = int(record['msecs_finish'])
                return
            
            match = self.regex_rowssize.match(payload)
            if match:
                record.update (match.groupdict())
                record['rows'] = int(record['rows'])
                record['size'] = int(record['size'])
                return
            
            match = self.regex_threads.match(payload)
            if match:
                record.update (match.groupdict())
                record['msecs_stop'] = int(record['msecs_stop'])
                record['threads_stop'] = int(record['threads_stop'])
                self.finish_record (id, timestamp, self.finish_normal)
                return
            
            match = self.regex_error.match(payload)
            if match:
                if 'error' in record:
                    print 'Existing error for id %s: %s' % (id, record['error'])
                    print 'New error:', match.group('error')
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

    def current_window_length_secs(self):

        current_timespan_usecs = self.newest_stop_time - self.oldest_start_time
        return current_timespan_usecs * 1e-6

    def finish_record (self, id, timestamp, finish_mode):

        self.data_D[id]['time_stop'] = timestamp 
        self.data_D[id]['state'] = self.status_stop
        self.data_D[id]['finish_mode'] = finish_mode 

        if self.newest_stop_time < timestamp: 
            self.newest_stop_time = timestamp


    def advance_records (self, line_in):

        self.parse_log_line(line_in)
        self.update()
        self.statistics.get_statistics(self.data_D)


class RecordStatistics(object):

    def __init__ (self, statistics_spec):

        self.stats_dict = { self.gen_statistic_id(stat):stat for stat in statistics_spec }
        self.stats_data = { self.gen_statistic_id(stat):{} for stat in statistics_spec }

    def get_statistics (self, source_dict):

        for stat_id, stat_spec in self.stats_dict.items():

            statistic = self.stats_data[stat_id]

            interest = stat_spec['interest']
            weighter = stat_spec['weighter']
            action = stat_spec['action']

            for element in source_dict.itervalues():

                if 'filter' in stat_spec:
                    filter_key, filter_val = stat_spec['filter'].items()[0]
                    if element[filter_key] != filter_val:
                        continue
                
                if interest in element:

                    interest_val = element[interest]
                    if weighter == 1:
                        weighter_val = 1
                    elif weighter in element:
                        weighter_val = element[weighter]
                    else:
                        continue

                    if interest_val not in statistic:
                        statistic[interest_val] = collections.Counter()

                    if action == 'tally':
                        statistic[interest_val][weighter_val] += 1
                    elif action == 'sum':
                        statistic[interest_val]['sum'] += weighter_val


    def get_ranks (self, num_ranks):

        rankings = {}

        for stat_id, stat_spec in self.stats_dict.items():
            statistic = self.stats_data[stat_id]
            try:
                rankings[stat_id] = sorted (statistic.items(), key=lambda e: e[1].most_common(num_ranks), reverse=True)[:num_ranks]
            except:
                sys.stdout.write("!!!! %s\n" % (str(statistic)))


        return rankings

    #TODO: Replace statistics spec with a class that inherits from dict
    def gen_statistic_id (self, stat_spec):
        
        interest = stat_spec['interest']
        weighter = stat_spec['weighter']
        action = stat_spec['action']

        if 'filter' in stat_spec:
            pre_id = "{0}=={1} ".format(*stat_spec['filter'].items()[0])
        else:
            pre_id = ''

        id = "{0} {1} by {2}".format(action, interest, weighter)

        return pre_id + id



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

