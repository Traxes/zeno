#!/usr/bin/env python3

import binaryninja
import argparse
import os
from avd.loader import PluginLoader
from avd.helper.drcov import DrcovData
import ntpath
import errno


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
        if not os.path.isfile(arg):
            parser.error("The file %s does not exist!" % arg)
        else:
            return arg  # return an open file handle


def path_leaf(path):
    """
    Gets a Path as argument and returns the filename
    :param path: </path/to/file>
    :return:
    """
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def plugin_filter(args, plugins):
    """
    Filters the available plugins and can order it.
    The blacklisting feature will always be the dominant one.
    Thus even with Ordering it will filter out the Blacklist.

    Whitelisting will prevent ordering and is mutually exclusive to the blacklisting feature.
    If you want to test your ordered Plugin list just use the blacklisting feature to play around.
    :param args:
    :param plugins:
    :return:
    """
    returning_plugins = list()
    # Blacklist Parsing
    if args.blacklist:
        for blacklist_module in args.blacklist.replace(" ", "").split(","):
            plugins.remove(blacklist_module)
    # Whitelist Parsing
    elif args.whitelist:
        for whitelist_module in args.whitelist.replace(" ", "").split(","):
            if whitelist_module in plugins:
                returning_plugins.append(whitelist_module)
        return returning_plugins

    if args.plugin_order:
        # Check if its a list
        if "," in args.plugin_order:
            for plugin_name in args.plugin_order.replace(" ", "").split(","):
                if plugin_name in plugins:
                    returning_plugins.append(plugin_name)
        else:
            # assume the given argument is a path to a file
            if not os.path.exists(args.plugin_order):
                OSError.NotADirectoryError(errno.ENOENT, os.strerror(errno.ENOENT), args.plugin_order)
            else:
                if not os.path.isfile(args.plugin_order):
                    raise OSError.FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), args.plugin_order)
                else:
                    # Parse the given file (Plugins splitted by newlines)
                    with open(args.plugin_order) as fin:
                        for plugin_name in fin:
                            if plugin_name in plugins:
                                returning_plugins.append(plugin_name)

    return returning_plugins if len(returning_plugins) > 0 else plugins


def main():
    """
    Main function. Also used for Commandline Parsing
    :return:
    """

    parser = argparse.ArgumentParser(description='Zeno Commandline tool: Searches Automagically for Bugs')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--blacklist', type=str,
                       help="Provide a blacklist seperated by commas. This will filter out not needed plugins")
    group.add_argument('-w', '--whitelist', help='Whitelist modules', type=str)

    parser.add_argument("--plugin_order", default=None, type=str,
                        dest="plugin_order", help="Provide a file with the plugins in the correct order to be loaded")

    parser.add_argument('--deep',
                        dest='deep', action='store_true',
                        help='Uses Deep Search mode. This might take longer but it will also get a grasp of compiler optimizations')
    parser.add_argument('--search-path',
                        dest='search_path', default="/lib:/usr/lib",
                        help='":" separated list of paths to search libraries in')
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

    #print(plugins.pprint_available_plugins())

    filtered_plugins = plugin_filter(args, [name for name, _ in plugins.available_plugins])

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

        print(filtered_plugins)
        for name in filtered_plugins:
            plugin = plugins.get_plugin_instance(name)
            plugin.vulns = []
            plugin.run(bv, args.deep)
            if args.coverage:
                plugin.set_traces(cov_bb)
            del plugin  # This will print the vulns.

    return



if __name__ == "__main__":
    main()
