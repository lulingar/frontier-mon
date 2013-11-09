# -*- coding: utf-8 -*-
import multiprocessing

import pandas as pd
import numpy as np
import dateutil as du

from datetime import datetime, timedelta
import dateutil
import TomcatLib
import Utils

#specifier = "cat.out.full.gz"
specifier = "cat.out.full"

def complete_tomcat_assemble (machine, out_q, start, end, time_bin, work_path):

    watch = TomcatLib.TomcatWatcher(20*60, True)
    recs = Utils.gather_stats(machine, [start, end, time_bin], watch, specifier, work_path,
                              TomcatLib.tomcat_aggregator, TomcatLib.get_timestamp,
                              TomcatLib.parse_tomcat_timedate, max_in_core=120e3)
    out_q.put((machine, recs))

def main ():

    work_path = '/afs/cern.ch/user/l/llinares/work/private/frontier/madgraph_incident_201309/'

    start = datetime(2013, 9, 7, 3, 0, 0, tzinfo=dateutil.tz.tzlocal())
    end = datetime(2013, 9, 8, 23, 0, 0, tzinfo=dateutil.tz.tzlocal())
    time_bin = timedelta(minutes=2)

    tic = datetime.now()

    tomcat_q = multiprocessing.Queue()
    processes = []
    for machine in (1, 2, 3):
        p = multiprocessing.Process(target = complete_tomcat_assemble,
                                    args = (machine, tomcat_q, start, end, time_bin, work_path))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    agg = Utils.aggregator(work_path, specifier)
    csv_file = work_path + 'tomcat_aggregation.csv'
    agg.to_csv(csv_file, index=False)
    print "File {0} written.".format(csv_file)

    print "Tomcat elapsed:", str(datetime.now() - tic)

if __name__ == "__main__":
    main()
