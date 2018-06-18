from .. import Plugin

__all__ = ['PluginBufferOverflow']

class PluginBufferOverflow(Plugin):
    name = "bo"
    display_name = "Buffer Overflow"
    cmd_name = "bo"
    cmd_help = "Search for Known Buffer Overflow patterns"

    def __init__(self):
        super(PluginBufferOverflow, self).__init__()

    def run(self, bv):
        super(PluginBufferOverflow, self).run(bv)
        print "INSIDE THE PLUGIN ! arch: {0} | platform: {1}".format(bv.arch, bv.platform)
        print("FOOO")