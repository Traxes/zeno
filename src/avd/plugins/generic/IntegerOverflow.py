from src.avd.plugins import Plugin
from tqdm import tqdm
from binaryninja import SSAVariable, MediumLevelILOperation
from src.avd.reporter.vulnerability import Vulnerability
from src.avd.helper import sources
from z3 import *

__all__ = ['PluginIntegerOverflow']


class PluginIntegerOverflow(Plugin):
    name = "PluginIntegerOverflow"
    display_name = "Integer Overflow"
    cmd_name = "io"
    cmd_help = "Search for Integer Overflows."

    _value_ops = [
        MediumLevelILOperation.MLIL_ADD,
        MediumLevelILOperation.MLIL_ADC,
        MediumLevelILOperation.MLIL_DIVS,
        MediumLevelILOperation.MLIL_MUL,
        MediumLevelILOperation.MLIL_SUB
    ]

    def __init__(self, bv=None):
        super(PluginIntegerOverflow, self).__init__(bv)
        self.bv = bv

    def set_bv(self, bv):
        self.bv = bv

    def run(self, bv=None, args=None, traces=None):
        super(PluginIntegerOverflow, self).__init__(bv)
        self._find_int_overflow()
        return

    def _check_maybe_constrolled(self, instr, var):
        slice_sources = self.slice_engine.get_sources2(self.bv, instr, var)
        return [x for x in slice_sources if x in sources.user_sources]

    def _check_if_value_operation(self, instr):
        for ops in instr.operands:
            if hasattr(ops, "operation"):
                if ops.operation in self._value_ops:
                    right_ops_sources = self._check_maybe_constrolled(instr, ops.right.src)
                    left_ops_sources = self._check_maybe_constrolled(instr, ops.left.src)
                    if len(right_ops_sources) or len(left_ops_sources):
                        # Stupid Approach at first
                        # Part of the Instruction can be attacker Controlled.
                        text = "MLIL {} 0x{:x}\n".format(instr.function.source_function.name, instr.address)
                        text += "\t\tPotential Integer Overflow\n\t\tInstruction: {}\n".format(instr.non_ssa_form)
                        if right_ops_sources:
                            text += "\t\t\t Variable {} might be attacker controlled with {}\n".format(
                                ops.right.src, str(right_ops_sources))
                        if left_ops_sources:
                            text += "\t\t\t Variable {} might be attacker controlled with {}\n".format(
                                ops.left.src, str(left_ops_sources))

                        vuln = Vulnerability("Potential Integer Overflow problem!",
                                             text,
                                             instr,
                                             "It appears that parts of the calculation can be attacker controlled",
                                             60)
                        self.vulns.append(vuln)
                        # TODO Perform z3 Analysis to check for multiple problems


                        # https://github.com/0vercl0k/z3-playground/blob/master/proof_unsigned_integer_overflow_chech.py
                        #ops.possible_values
                        #left_var = BitVecs('left_var', ops.left.src.width * 8)
                        #right_var = BitVecs('right_var', ops.right.src.width * 8)

    def _find_int_overflow(self):
        for func in tqdm(self.bv.functions, desc=self.name, leave=False):
            # Only check one function
            if not func.start == 0x16ab:
                continue
            for bb in func.medium_level_il.ssa_form:
                for instr in bb:
                    if not instr.instr_index == 41:
                        continue
                    # Usually int operations are at the very beginning SET_VAR operations
                    if instr.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                        if self._check_if_value_operation(instr):
                            print(instr)




