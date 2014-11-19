# -*- coding: utf-8 -*-

import multiprocessing as mp
import os
import sys

import pandas as pd

from datetime import datetime, timedelta
import SquidLib
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
    print "Squid elapsed:", str(toc - tic)
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

    # While frontier-squid outputs correct timestamps, fix issue with CERN
    # squid logs
    start += timedelta(hours=2)
    end += timedelta(hours=2)

    return specifier, work_path, start, end, time_bin

def generate_assemblies (specifier, work_path, start, end, time_bin):

    machines = os.listdir(work_path)

    print "Generating assemblies..."
    processes = [ mp.Process(target = complete_squid_assemble,
                             args = (machine, start, end, time_bin, specifier, work_path))
                 for machine in machines ]

    print "Starting processes"
    [ p.start() for p in processes ]

    [ p.join() for p in processes ]
    """
    for machine in (3, 2, 1):
        complete_squid_assemble(machine, start, end, time_bin, specifier, work_path)
    """

    print "All finished"

def assemble (specifier, work_path, start, end):

    contents = os.listdir(work_path)
    machines = ( name for name in contents if os.path.isdir(os.path.join(work_path, name)) )

    print "Assembling data..."
    ag = []
    for idx in machines:
        filename = os.path.join(work_path, str(idx), specifier + ".assembly.csv")
        print "Reading", filename

        df = pd.read_csv(filename, index_col=None)
        df["machine"] = idx
        ag.append(df)

    agg = pd.concat(ag)
    #agg.time_start = pd.to_datetime( agg.time_start, utc=True, unit='us')
    #agg.time_end = pd.to_datetime( agg.time_end, utc=True, unit='us')
    agg.sort( columns=['time_start'], inplace=True)

    csv_file = os.path.join(work_path, 'squid_aggregation.csv')
    agg.to_csv(csv_file, index=False)
    print "File {0} written.".format(csv_file)

def complete_squid_assemble (machine, start, end, time_bin, specifier, work_path):

    watch = SquidLib.SquidWatcher(20*60, True)
    log_file = os.path.join(work_path, str(machine), specifier)
    recs = Utils.gather_stats( machine, [start, end, time_bin], watch, log_file,
                               query_aggregator, SquidLib.get_timestamp,
                               SquidLib.parse_squid_timedate,
                               SquidLib.find_log_offset, max_in_core=120e3 )

    filename = os.path.join(work_path, str(machine), specifier + ".assembly.csv")
    recs.to_csv(filename, index=False)
    print "Written:", filename

    return True

def query_aggregator (block_dataframe):

    group_fields = ['servlet', 'who', 'fid_sw_release', 'fid_userdn', 'hierarchy_status']
    sq_st = block_dataframe

    start = int( sq_st.timestamp.min())
    end = int( sq_st.timestamp.max())

    sq_st.http_code /= 100
    sq_st.http_code = sq_st.http_code.map(SquidLib.series)
    _s0 = sq_st.groupby(group_fields + ['http_code']).size().unstack()

    _s1 = sq_st.groupby(group_fields).agg({'size': ['min', 'max', 'sum'],
                                           'duration': ['min', 'max', 'mean']})

    _s0.columns = ["{0}_{1}".format(_s0.columns.name, col) for col in _s0.columns.values]
    _s1.columns = map(str.strip, map('_'.join, _s1.columns.values))

    df = _s0.join([_s1])
    df['time_start'] = start
    df['time_end'] = end
    df['span'] = (end - start)

    return df.reset_index()

if __name__ == "__main__":
    sys.exit(main())
