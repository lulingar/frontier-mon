import fileinput
import sys

from Utils import decode_frontier, get_hostname
from TomcatLib import TomcatWatcher

tw = TomcatWatcher(3, True)

def main ():

    for line in fileinput.input():
        tw.advance_records (line)

if __name__ == "__main__":
    sys.exit(main())

