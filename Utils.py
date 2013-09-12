#!/usr/bin/env python

import collections
#import json
import time

def current_utc_time_usecs():
    return int (1e6 * time.time())

class Counter:

    def __init__ (self, iterable_or_mapping=None, **kwargs):

        self.counter = {}

        if isinstance (iterable_or_mapping, dict):
            self.counter.update (iterable_or_mapping)
        elif iterable_or_mapping:
            for element in iterable_or_mapping:
                self.add (element)

        self.counter.update(kwargs)

    def add (self, element, quantity=1):

        if element not in self.counter:
            self.counter[element] = quantity
        else:
            self.counter[element] += quantity

    def substract (self, element, quantity=1):

        if element in self.counter:
            self.counter[element] -= quantity

        if self.counter[element] <= 0:
            self.counter.pop (element)

    def most_common (self, ranks=float('inf')):

        rank = self.counter.items()
        rank.sort (key = lambda e: e[1], reverse=True)
        last_index = min (len(rank), ranks)
        return rank[0:last_index]


class TimeWindowedRecord:

    def __init__ (self, window_length_secs, now=None):

        self.window_length_V = int (window_length_secs*1e6)
        self.history_H = collections.deque() 
        self.interval_sum_L = 0

        self.access_counter = Counter()

        self.serial_obj = {'window': self.window_length_V,
                           'history': self.history_H}

        if not now:
            now = current_utc_time_usecs()
        self.last_time = now 

    def event (self, in_object, now=None):

        if not now:
            now = current_utc_time_usecs()
        interval = now - self.last_time
        self.last_time = now

        event = [interval, in_object]
        self.access_counter.add (in_object)

        self.interval_sum_L += interval

        while self.interval_sum_L > self.window_length_V and self.history_H:
            interval_out, object_out = self.history_H.popleft()
            self.interval_sum_L -= interval_out
            self.access_counter.substract (object_out)

        self.history_H.append (event)

    def current_window_length_secs (self):
        return self.interval_sum_L*1e-6

    def most_frequent (self, ranks):
        return self.access_counter.most_common (ranks)

    """
    def serialize (self):
        return json.dumps( , indent=2)
    """

# Testing code
if __name__ == "__main__":

    import random
    import threading

    object_bag = ["algo", "bueeenas", "dksdjiw", "dykstra", "agent", "test"]
    watch = TimeWindowedRecord (2)

    def feed_events (signal):
        while not signal.isSet():
            signal.wait( 1*random.random() )
            print "<feed!>"
            watch.event( random.choice(object_bag))

    def show_window (signal):
        while not signal.isSet():
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



