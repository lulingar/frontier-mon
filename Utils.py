import collections
import functools
import json
import time

from heapq import nsmallest
from operator import itemgetter

def current_utc_time_usecs():
    return int (1e6 * time.time())

class TimeWindowedRecord:

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
            #self.access_counter += collections.Counter()

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

