import fileinput
import os
import sys
import time

import numpy as np
import pandas as pd

from Utils import decode_frontier, get_hostname
from TomcatLib import TomcatWatcher, count_sum_stats, render_indices


tw = TomcatWatcher(10*60, True)

def main ():

    hashes = tw.data_D.hash_table
    variables = tw.data_D.column_table
    raw_table = tw.data_D.data_table
    finish_codes = hashes['finish_mode']

    tops = count_sum_stats
    render = render_indices

    for line in fileinput.input():
        tw.advance_records (line)

        lines = ["At %s for the last %.2f seconds:" % ( time.strftime("%d/%b/%Y %H:%M:%S"), tw.current_window_length_secs() )]
        lines.append("tam: %d" % (len(tw)))

        if tw.current_window_length_secs() < 0:
            #TODO: fill dataframe more efficiently
            data = pd.DataFrame(raw_table, columns=list(variables)).dropna(how='all', axis=0)

            servlets = np.array(data.servlet.dropna().unique(), dtype=int)

            finished_ones = data[data['finish_mode'] == finish_codes[tw.finish_normal]]
            hierarchy = ['servlet', 'query', 'who']
            num_stats = 12

            by_SBW_group = finished_ones.groupby(hierarchy)['size']
            by_SBW = render( tops( by_SBW_group, 0.8).head(num_stats), hashes)

            by_duration_group = finished_ones.groupby(hierarchy)['duration']
            by_duration = render( tops( by_duration_group, 0.8).head(num_stats), hashes)

            lines.append('by size:')
            lines.append(str(by_SBW))
            lines.append('by duration:')
            lines.append(str(by_duration))

        out_text = '\n'.join(lines)

if __name__ == "__main__":
    sys.exit(main())

