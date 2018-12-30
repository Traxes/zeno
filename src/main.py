#!/usr/bin/env python3

import binaryninja
import argparse
import os
from avd.loader import PluginLoader
from avd.helper.drcov import DrcovData
import ntpath


def is_valid_file(parser, arg):
    """
    Checks if the given argument is a valid file
    :param parser:
    :param arg: </path/to/file>
    :return: file path if valid
    """
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg  # return an open file handle

def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

def main():
    """
    Main function. Also used for Commandline Parsing
    :return:
    """

    parser = argparse.ArgumentParser(description='AVD Commandline tool: Searches Automagically for Bugs')
    parser.add_argument('--deep',
                        dest='deep', action='store_true',
                        help='Uses Deep Search mode. This might take longer but it will also get a grasp of compiler optimizations')
    parser.add_argument('--search-path',
                        dest='search_path', default="/lib:/usr/lib",
                        help='":" seperated list of paths to search libraries in')
    parser.add_argument('target', metavar='target-path', nargs='+',
                        help='Binary to be analysed',
                        type=lambda x: is_valid_file(parser, x))
    parser.add_argument("--system-root", default="/",
                        dest="root", help="Use paths relative to this root for library searching")

    parser.add_argument("--dot", default=None,
                        dest="outputfile", help="Write graph to a dotfile")

    parser.add_argument("--cov", default=None,
                        dest="coverage", help="Provide a coverage file for better filtering")

    parser.add_argument("--cov_folder", default=None,
                        dest="cov_folder", help="Provide a folder with coverage files for better filtering")

    plugins = PluginLoader(argparser=parser)
    args = parser.parse_args()

    content = plugins.read_content_from_args()
    print(plugins.pprint_available_plugins())


    # Start Working with the Binaries here
    input_file = args.target
    for filename in input_file:
        print("Analyzing {0}".format(filename))
        bv = binaryninja.BinaryViewType.get_view_of_file(filename)
        if args.coverage:
            print("Single Coverage given")
            cov = DrcovData(args.coverage)
            cov_bb = cov.get_blocks_by_module(path_leaf(filename))
            # TODO Insert to Plugin Analyser
        if args.cov_folder:
            # TODO Make multi Coverage possible
            pass

        print("arch: {0} | platform: {1}".format(bv.arch, bv.platform))
        bv.update_analysis_and_wait()
        for name, _ in plugins.available_plugins:
            plugin = plugins.get_plugin_instance(name)
            plugin.vulns = []
            plugin.run(bv, args.deep)
            if args.coverage:
                plugin.set_traces(cov_bb)
            del plugin  # This will print the vulns.

    return



if __name__ == "__main__":
    main()
