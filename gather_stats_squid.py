# -*- coding: utf-8 -*-

import multiprocessing

import pandas as pd
import numpy as np
import dateutil as du

from datetime import datetime, timedelta
import dateutil
import SquidLib
import Utils

#specifier = "sqd.log.full.gz"
specifier = "sqd.log.full"

def complete_squid_assemble (machine, out_q, start, end, time_bin, work_path):

    watch = SquidLib.SquidWatcher(20*60, True)
    recs = Utils.gather_stats( machine, [start, end, time_bin], watch, specifier, work_path,
                               SquidLib.squid_aggregator, SquidLib.get_timestamp,
                               SquidLib.parse_squid_timedate, max_in_core=120e3 )
    out_q.put((machine, recs))

def main ():

    work_path = '/afs/cern.ch/user/l/llinares/work/private/frontier/madgraph_incident_201309/'

    start = datetime(2013, 9, 7, 3, 0, 0, tzinfo=dateutil.tz.tzlocal())
    end = datetime(2013, 9, 8, 23, 0, 0, tzinfo=dateutil.tz.tzlocal())
    time_bin = timedelta(minutes=2)

    tic = datetime.now()

    squid_q = multiprocessing.Queue()
    processes = []
    for machine in (1, 2, 3):
        p = multiprocessing.Process(target = complete_squid_assemble,
                                    args = (machine, squid_q, start, end, time_bin, work_path))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    ag = {}
    for idx in (1, 2, 3):
        filename = "{2}/{0:d}/{1}.assembly.csv".format(idx, specifier, work_path)
        print "Reading", filename
        ag[idx] = pd.read_csv(filename)

    agg = Utils.aggregator(ag, "machine")
    agg = agg[agg.time_start.notnull()]
    agg.time_start = pd.to_datetime(agg.time_start, utc=True, unit='us')
    agg.time_end = pd.to_datetime(agg.time_end, utc=True, unit='us')
    agg.sort( columns=['time_start'], inplace=True)
    agg.fillna( 0, inplace=True)

    csv_file = work_path + 'squid_aggregation.csv'
    agg.to_csv(csv_file, index=False)
    print "File {0} written.".format(csv_file)

    print "Squid elapsed:", str(datetime.now() - tic)

if __name__ == "__main__":
    main()

