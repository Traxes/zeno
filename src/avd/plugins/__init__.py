"""
Loader shamelessly stolen from Niklaus Schiess deen ;-) https://github.com/takeshixx/deen
"""
from binaryninja.binaryview import BinaryView
import sys
from collections import Counter
from ..helper.binjaWrapper import get_basic_block_from_instr
from src.avd.core.sliceEngine.slice import SliceEngine

#from .bo import PluginBufferOverflow


class Plugin(object):
    """The core plugin class that should be subclassed
    by every plugin. It provides some required
    class attributes that ease the process of writing
    new plugins."""

    # In case an error happened, it should
    # be stored in this variable.
    error = None
    # Internal name for the plugin.
    name = ''
    # The name that will be displayed in the GUI.
    display_name = ''
    # A list of aliases for this plugin. Can
    # be empty if there is no aliases to the
    # plugin name.
    aliases = []

    # List of vulnerabilities found.
    vulns = []

    # Traces
    _traces = []

    # BinaryView from BinaryNinja
    _binaryView = None

    # Arguments for better handling
    _args = None

    # Reference to the Slice Engine
    slice_engine = None

    def __init__(self, bv, args=None):
        self._binaryView = bv
        self._args = args
        self.slice_engine = SliceEngine(args)

    def __del__(self):
        if len(self.vulns) > 0:
            for vuln in sorted(self.vulns, key=lambda x: x.probability, reverse=True):
                if len(self._traces) > 0:
                    bb = get_basic_block_from_instr(self.bv, vuln.instr.address)
                    vuln.cmd_print_finding(self._traces, bb)
                else:
                    vuln.cmd_print_finding()

    @property
    def bv(self):
        return self._binaryView

    @bv.setter
    def bv(self, bv):
        self._binaryView = bv

    def set_traces(self, traces):
        self._traces = traces

    def append_vuln(self, v):
        """
        This function prevents to have duplicate vulnerabilties
        :param Vulnerability v:
        :return None:
        """
        if not [e_vuln for e_vuln in self.vulns if not e_vuln != v]:
            self.vulns.append(v)

    @staticmethod
    def prerequisites():
        """A function that should return True if all
        prerequisites for this plugin are met or False
        if not. Here a plugin can e.g. check if the
        current Python version is suitable for the
        functionality or if required third party modules
        are installed."""
        return True

    def run(self, bv):
        """
        Every plugin must have a run method to execute the plugin and perform the analysis
        :param bv:
        :return:
        """
        assert bv is not None
        assert isinstance(bv, BinaryView)


    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None):
        """This function allows plugins to add subcommands
        to argparse in order to be used via a seperate
        command/alias on the CLI.

        :param argparser: a ArgParser object
        :param cmd_name: a plugin's cmd_name class variable
        :param cmd_help: a plugin's cmd_help class variable
        :param cmd_aliases: a plugin's cmd_aliases class variable
        """
        if not cmd_aliases:
            cmd_aliases = []
        # Note: Python 2 argparse does not support aliases.
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 2):
            parser = argparser.add_parser(cmd_name, help=cmd_help)
        else:
            parser = argparser.add_parser(cmd_name, help=cmd_help, aliases=cmd_aliases)
        parser.add_argument('plugindata', action='store',
                            help='input data', nargs='?')
        parser.add_argument('-r', '--revert', action='store_true', dest='revert',
                            default=False, help='revert plugin process')
        parser.add_argument('-f', '--file', dest='plugininfile', default=None,
                            help='file name or - for STDIN')

    def process_cli(self, args):
        # TODO Fix CLI parameters
        """Do whatever the CLI cmd should do. The args
        argument is the return of parse_args(). Must
        return the processed data.

        :param args: the output of argparse.parse_args()
        :return: the return of either process() or unprocess()
        """
        if not self.content:
            if not args.plugindata:
                if not args.plugininfile:
                    self.bv = self.read_content_from_file('-')
                else:
                    self.bv = self.read_content_from_file(args.plugininfile)
            else:
                self.bv = args.plugindata
        if not self.bv:
            return
        return self.run(self.bv)


    def read_content_from_file(self, file):
        """If file is a filename, it will read and
        return it's content. If file is '-', read
        from STDIN instead of a file.

        :param file: filename of '-' for STDIN
        :return: content of filename or data from STDIN
        """
        content = b''
        try:
            if file == '-':
                try:
                    stdin = sys.stdin.buffer
                except AttributeError:
                    stdin = sys.stdin
                content = stdin.read()
            else:
                try:
                    with open(file, 'rb') as f:
                        content = f.read()
                except Exception as e:
                    self.error = e
        except KeyboardInterrupt:
            return
        return content

    def write_to_stdout(self, data, nonewline=False):
        """Write processed data to STDOUT. It takes
        care of whether it's running in Python 2 or 3
        to properly write bytes to STDOUT.

        :param data: data to be written to STDOUT
        :param nonewline: if True, omit newline at the end
        """
        try:
            # Python 3
            stdout = sys.stdout.buffer
        except AttributeError:
            # Python 2
            stdout = sys.stdout
        stdout.write(data)
        if not nonewline:
            stdout.write(b'\n')