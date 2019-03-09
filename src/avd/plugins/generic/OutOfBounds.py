from src.avd.plugins import Plugin
#from ..reporter.vulnerability import Vulnerability
#from ..helper import binjaWrapper, sources
#import re
#import collections
#import traceback
#from src.avd.core.sliceEngine import slice
from src.avd.core.sliceEngine.loopDetection import loop_analysis
#from binaryninja import MediumLevelILOperation, RegisterValueType, SSAVariable
#from sys import maxsize

__all__ = ['PluginOutOfBounds']


class PluginOutOfBounds(Plugin):
    name = "PluginOutOfBounds"
    display_name = "Out of Bounds"
    cmd_name = "oob"
    cmd_help = "Search for Out of Bounds Access"

    def __init__(self, bv=None):
        super(PluginOutOfBounds, self).__init__(bv)
        self.bv = bv

    def set_bv(self, bv):
        self.bv = bv

    def run(self, bv=None, args=None, traces=None):
        super(PluginOutOfBounds, self).__init__(bv)
        #self.find_possible_arrays()
        return

    def find_possible_arrays(self):
        """
        Searches for possible array declerations on mlil. Later SSA will be used to triage
        :return:
        """
        array_def_functions = ["MLIL_SET_VAR", "MLIL_CONST_PTR"]
        for func in self.bv.functions:
            func_ssa = func.medium_level_il
            for bb in func_ssa:
                for instr in bb:
                    if instr.operation.name in array_def_functions:
                        #for bb in self.bv.get_basic_blocks_at(instr.address):
                            #if loop_analysis(bb):
                        # TODO find whether the var is used either in a loop or access directly
                        # https://github.com/cetfor/PaperMachete/blob/master/queries/cwe_788_v1.py
                        pass
                        #print(instr)
