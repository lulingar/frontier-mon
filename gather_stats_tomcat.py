# -*- coding: utf-8 -*-
import multiprocessing as mp
import os
import sys

import pandas as pd

from datetime import datetime, timedelta
import TomcatLib
import Utils

def main ():

    specifier, work_path, start, end, time_bin = parse_commandline()
    if specifier is None:
        return 1

    print "Range:", start, "to", end
    tic = datetime.now()

    generate_assemblies(specifier, work_path, start, end, time_bin)
    assemble(specifier, work_path, start, end)

    toc = datetime.now()
    print "Tomcat elapsed:", str(toc - tic)
    return 0

def parse_commandline():

    if len(sys.argv) != 6:
        print "Usage: %s files-name files-base-path start-datetime end-datetime time-bin"
        return [None]*5

    specifier = sys.argv[1]                                       # File name (e.g. "catalina.out")
    work_path = os.path.expanduser(sys.argv[2])          # Base path (e.g. "~/some_dirs/base_dir/")
    start = Utils.simple_datetime_entry(sys.argv[3])  # A datetime (e.g. "2014-03-02 07:34:12 CET")
    end = Utils.simple_datetime_entry(sys.argv[4])  # A datetime (e.g. "2014-03-02 09:00:00 +0100")
    time_bin = timedelta(minutes = int(sys.argv[5]))        # Aggregation resolution bin in minutes

    return specifier, work_path, start, end, time_bin

def generate_assemblies (specifier, work_path, start, end, time_bin):

    print "Generating assemblies..."
    processes = [ mp.Process(target = complete_tomcat_assemble,
                             args = (machine, start, end, time_bin, specifier, work_path))
                 for machine in (1, 2, 3) ]

    print "Starting processes"
    [ p.start() for p in processes ]

    [ p.join() for p in processes ]
    """
    for machine in (3, 2, 1):
        complete_tomcat_assemble(machine, start, end, time_bin, specifier, work_path)
    """

    print "All finished"

def assemble (specifier, work_path, start, end):

    print "Assembling data..."
    ag = {}
    for idx in (1, 2, 3):
        filename = os.path.join(work_path, str(idx), specifier + ".assembly.csv")
        print "Reading", filename
        ag[idx] = pd.read_csv(filename)
        """
        index, dataframe = tomcat_q.get()
        print "Reading", index
        ag[index] = dataframe
        """

    agg = Utils.aggregator(ag, "machine")
    agg = agg[ agg.time_start.notnull() ]
    agg.time_start = pd.to_datetime(agg.time_start, utc=True, unit='us')
    agg.time_end = pd.to_datetime(agg.time_end, utc=True, unit='us')
    agg.sort( columns=['time_start'], inplace=True)
    agg.fillna( 0, inplace=True)

    csv_file = os.path.join(work_path, 'tomcat_aggregation.csv')
    agg.to_csv(csv_file, index=False)
    print "File {0} written.".format(csv_file)

def complete_tomcat_assemble (machine, start, end, time_bin, specifier, work_path):

    watch = TomcatLib.TomcatWatcher(20*60, True)
    log_file = os.path.join(work_path, str(machine), specifier)
    recs = Utils.gather_stats( machine, [start, end, time_bin], watch, log_file,
                               query_aggregator, TomcatLib.get_timestamp,
                               TomcatLib.parse_tomcat_timedate,
                               TomcatLib.find_log_offset, max_in_core=120e3 )

    filename = os.path.join(work_path, str(machine), specifier + ".assembly.csv")
    recs.to_csv(filename, index=False)
    print "Written:", filename

    return True

def query_aggregator (block_dataframe):

    group_fields = ['servlet', 'sql', 'fid', 'who', 'fwd']
    tw_st = block_dataframe

    start = int( tw_st.time_start.min())
    end = int( tw_st.time_start.max())

    _s0 = tw_st.groupby(group_fields + ['state']).size().unstack()
    _s1 = tw_st.groupby(group_fields + ['finish_mode']).size().unstack()
    _s2 = tw_st.groupby(group_fields).agg({'threads_start': 'max',
                                           'threads_stop': 'max',
                                           'size': 'sum',
                                           'error': 'count',
                                           'duration': ['min', 'max', 'sum'],
                                           'msecs_acq': 'sum',
                                           'msecs_finish': 'sum',
                                           'msecs_stop': 'sum'})

    _s0.columns = ["{0}_{1}".format(_s0.columns.name, col) for col in _s0.columns.values]
    _s1.columns = ["{0}_{1}".format(_s1.columns.name, col) for col in _s1.columns.values]
    _s2.columns = map(str.strip, map('_'.join, _s2.columns.values))

    df = _s0.join([_s1, _s2])
    df['time_start'] = start
    df['time_end'] = end
    df['span'] = (end - start)/1e6

    return df.reset_index()

if __name__ == "__main__":
    sys.exit(main())
