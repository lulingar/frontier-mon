import fileinput
import os
import sys
import threading
import time

from Utils import count_sum_stats, render_indices
from SquidLib import SquidWatcher

def main ():

    threads_signal = threading.Event()

    threads = [threading.Thread (name='log', target=log_thread, args=(threads_signal,)),
               threading.Thread (name='print', target=print_thread, args=(threads_signal,))]

    for thread in threads: thread.start()

    try:
        while True: time.sleep(100)
    except (KeyboardInterrupt, SystemExit):
        threads_signal.set()
        for thread in threads: thread.join()

    return 0


def log_thread (signal):

    for line in fileinput.input():

        record = parse_log_line (line)

        if 'fid_userdn' in record:

            #user_stats.event ("%s#%s" % (record['client_ip'], record['fid_userdn']))
            user_stats.event (record['client_ip'])
            query_stats.event ("%s#%s" % (record['servlet'], record['query']))

        if signal.is_set(): break


def print_thread (signal):

    while not signal.is_set():

        lines = ["At %s for the last %.2f seconds:" % ( time.strftime("%d/%b/%Y %H:%M:%S"), query_stats.current_window_length_secs() )]

        lines.append ('')
        lines.append ("Query stats:")
        for query, amount in query_stats.most_frequent(10):
            lines.append ("  -> (%d): %s" % (amount, decode_frontier(query)))

        lines.append ('')
        lines.append ("User stats:")
        for user, amount in user_stats.most_frequent(10):
            lines.append ("  -> (%d): %s" % (amount, get_hostname(user)))

        out_text = '\n'.join(lines)

        fout = open (os.path.expanduser('~/www/test.txt'), 'w')
        #fout.write (out_text)
        fout.write (user_stats.serialize())
        fout.close()

        print chr(27) + "[2J"
        print out_text

        #print record['timestamp'], '(%s)' % record['fid_userdn'], record['client_ip'], record['fid_sw_release'], record['size'], record['fid_uid'], '>', record['server'], record['query'], record['servlet']

        signal.wait(1)


)

from Utils import current_utc_time_usecs, TimeWindowedRecord, decode_frontier, get_hostname


if __name__ == '__main__':
    sys.exit(main())
