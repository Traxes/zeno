from src.avd.plugins import Plugin
from tqdm import tqdm
from binaryninja import SSAVariable, MediumLevelILOperation
from src.avd.reporter.vulnerability import Vulnerability

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

    def run(self, bv=None, deep=None, traces=None):
        super(PluginIntegerOverflow, self).__init__(bv)
        self._find_int_overflow()
        return

    def _check_if_value_operation(self, instr):
        for ops in instr.operands:
            if hasattr(ops, "operation"):
                if (ops.operation == MediumLevelILOperation.MLIL_ZX) or \
                        (ops.operation == MediumLevelILOperation.MLIL_SX):
                    for ops2 in ops.operands:
                        if hasattr(ops2, "operation"):
                            if ops2.operation in self._value_ops:  # TODO other ops
                                return True

    def _find_int_overflow(self):
        for func in tqdm(self.bv.functions, desc=self.name, leave=False):
            # Only check one function
            if not func.start == 0xd20:
                continue
            for bb in func.medium_level_il.ssa_form:
                for instr in bb:
                    # Usually int operations are at the very beginning SET_VAR operations
                    if instr.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                        if self._check_if_value_operation(instr):
                            print(instr)




