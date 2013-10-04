import fileinput
import sys
import os
import threading
import time

import numpy as np
import pandas as pd

from Utils import decode_frontier, get_hostname
from TomcatLib import TomcatWatcher, count_sum_stats, render_indices


tw = TomcatWatcher(7*60, True)

def main ():

    threads_signal = threading.Event()
    lock = threading.Lock()

    threads = [threading.Thread (name='log', target=log_thread, args=(threads_signal, lock,)),
               threading.Thread (name='print', target=print_thread, args=(threads_signal, lock,))]

    for thread in threads: thread.start()

    try:
        while True: time.sleep(100)
    except (KeyboardInterrupt, SystemExit):
        threads_signal.set()
        for thread in threads: thread.join()

    return 0


def log_thread (signal, lock):

    for line in fileinput.input():
        lock.acquire()
        tw.advance_records (line)
        lock.release()
        if signal.is_set(): break

def print_thread (signal, lock):

    hashes = tw.data_D.hash_table
    variables = tw.data_D.column_table
    raw_table = tw.data_D.get_raw_values
    finish_codes = hashes['finish_mode']

    tops = count_sum_stats
    render = render_indices

    timing = np.zeros((10,))

    hierarchy = ['servlet', 'query', 'who']
    num_stats = 12

    while not signal.is_set():

        idx = 0
        tic = time.time()

        lines = ["At %s for the last %.2f seconds:" % ( time.strftime("%d/%b/%Y %H:%M:%S"), tw.current_window_length_secs() )]
        lines.append("tam: %d" % (len(tw)))

        if tw.current_window_length_secs() > 5:
            lock.acquire()
            data = pd.DataFrame( raw_table(), columns=list(variables))
            lock.release()
            toc = time.time()
            timing[idx] = toc - tic ; idx +=1; tic = toc

            #servlets = np.array(data.servlet.unique(), dtype=int)

            finished_ones = data[data['finish_mode'] == finish_codes[tw.finish_normal]]

            by_SBW_group = finished_ones.groupby(hierarchy)['size']
            by_SBW = render( tops( by_SBW_group, 0.8).head(num_stats), hashes)

            toc = time.time()
            timing[idx] = toc - tic ; idx +=1; tic = toc

            by_duration_group = finished_ones.groupby(hierarchy)['duration']
            by_duration = render( tops( by_duration_group, 0.8).head(num_stats), hashes)

            toc = time.time()
            timing[idx] = toc - tic ; idx +=1; tic = toc

            lines.append('by size:')
            lines.append(str(by_SBW))
            lines.append('by duration:')
            lines.append(str(by_duration))

        out_text = '\n'.join(lines)

        #print chr(27) + "[2J"
        #print out_text

        so_far = timing[:idx]
        total = so_far.sum()
        print lines[0]
        print "records:", len(tw)
        print "times [ms]:", (so_far*1e3).round().astype(int)
        print "as %:", (100*so_far/total).round().astype(int)
        print "efficiency [rec/s]:", (len(tw)/so_far).round().astype(int), '\n'

        """
        fout = open (os.path.expanduser('~/www/test.txt'), 'w')
        fout.write (out_text)
        fout.close()
        """
        signal.wait(1)


if __name__ == "__main__":
    sys.exit(main())

