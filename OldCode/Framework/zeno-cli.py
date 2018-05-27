#!/usr/bin/env python3

# Main File

import argparse
import binaryninja
from zeno.vulnClasses.sinks import Sinks

# pylint: disable=invalid-name





if __name__ == "__main__":

    PARSER = argparse.ArgumentParser(description='Searches Automagically for Bugs')
    PARSER.add_argument('--deep',
                        dest='deep', action='store_true',
                        help='Uses Deep Search mode. This might take longer but it will also get a grasp of compiler optimizations')
    PARSER.add_argument('--search-path',
                        dest='search_path', default="/lib:/usr/lib",
                        help='":" seperated list of paths to search libraries in')
    PARSER.add_argument('targets', metavar='target-path', nargs='+',
                        help='Binary to be analysed')
    PARSER.add_argument("--system-root", default="/",
                        dest="root", help="Use paths relative to this root for library searching")

    PARSER.add_argument("--dot", default=None,
                        dest="outputfile", help="Write graph to a dotfile")


    ARGS = PARSER.parse_args()


    # Start Parsing
    inputfile = ARGS.targets

    for filename in inputfile:
        print("Analyzing {0}".format(filename))
        bv = binaryninja.BinaryViewType.get_view_of_file(filename)
        print "arch: {0} | platform: {1}".format(bv.arch, bv.platform)
        bv.update_analysis_and_wait()
    
    

    # TODO Debug Stuff Delete Later
    s = Sinks()
    s.get().run(bv, ARGS.deep)