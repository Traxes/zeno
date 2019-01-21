from . import Plugin
from binaryninja import SSAVariable
from src.avd.reporter.vulnerability import Vulnerability

__all__ = ['PluginLargeStackFrame']


class PluginLargeStackFrame(Plugin):
    name = "PluginLargeStackFrame"
    display_name = "Large Stack Frame"
    cmd_name = "lsf"
    cmd_help = "Search for large stack buffers."

    # TODO make it dynamic with arguments
    _threshold = 150

    def __init__(self, bv=None):
        super(PluginLargeStackFrame, self).__init__(bv)
        self.bv = bv

    def set_bv(self, bv):
        self.bv = bv

    def run(self, bv=None, deep=None, traces=None):
        super(PluginLargeStackFrame, self).__init__(bv)
        self._find_large_stack_frames()
        return

    @staticmethod
    def _calc_size(var, func):
        if SSAVariable == type(var):
            var = var.var

        if len(func.stack_layout) - 1 == func.stack_layout.index(var):
            return abs(var.storage)
        else:
            return abs(var.storage) - abs(func.stack_layout[func.stack_layout.index(var) + 1].storage)

    def _find_large_stack_frames(self):
        for func in self.bv.functions:
            for var in func.stack_layout:
                size = self._calc_size(var, func)
                if size >= self._threshold:
                    text = "{} 0x{:x}\n".format(func.name, func.start)
                    text += "\t\tFound Large Stack Variable: {0} with size {1} in function {2} at address {3}".format(
                        var.name, size, var.function.name, hex(var.function.start))

                    vuln = Vulnerability("Large Stack Frame!",
                                         text,
                                         None,
                                         "Large Stack Frames can be an indicator of potential misuse.",
                                         30)
                    self.vulns.append(vuln)
