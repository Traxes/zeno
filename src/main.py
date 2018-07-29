#!/usr/bin/env python3

import binaryninja
import argparse
import os
from avd.loader import PluginLoader


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

    plugins = PluginLoader(argparser=parser)
    args = parser.parse_args()

    content = plugins.read_content_from_args()
    print(plugins.pprint_available_plugins())


    # Start Working with the Binaries here
    input_file = args.target
    for filename in input_file:
        print("Analyzing {0}".format(filename))
        bv = binaryninja.BinaryViewType.get_view_of_file(filename)
        print "arch: {0} | platform: {1}".format(bv.arch, bv.platform)
        bv.update_analysis_and_wait()
        for name, _ in plugins.available_plugins:
            plugin = plugins.get_plugin_instance(name)
            plugin.run(bv, args.deep)
            del plugin

    return



if __name__ == "__main__":
    main()
