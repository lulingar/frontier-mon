import fileinput
import json
import sys
import os
import threading
import time

from Utils import current_utc_time_usecs, parse_utc_time_usecs, TomcatWatcher

tw = TomcatWatcher(10, True)

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
        tw.advance_records (line)
        if signal.is_set(): break


def print_thread (signal):
   
    while not signal.is_set():

        lines = ["At %s for the last %.2f seconds:" % ( time.strftime("%d/%b/%Y %H:%M:%S"), tw.current_window_length_secs() )]
        """
        lines.append('%d' % len(tw.history_H))
        for id, record in tw.data_D.items():
            lines.append('%s' % json.dumps(record, indent=2))
        """
        rankings = tw.statistics.get_ranks(10) 

        for stat_id, ranking in rankings.items():
            lines.append ('')
            lines.append (stat_id + ":")
            for rank, val in enumerate(ranking):
                lines.append ("  -> (%d): %s" % (rank+1, val))

        out_text = '\n'.join(lines)

        print chr(27) + "[2J"
        print out_text

        fout = open (os.path.expanduser('~/www/test.txt'), 'w')
        fout.write (out_text)
        fout.close()

        signal.wait(1)
            

if __name__ == "__main__":
    sys.exit(main())

