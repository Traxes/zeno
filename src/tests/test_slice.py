import unittest
import binaryninja

from src.avd.loader import PluginLoader
from src.avd.core.sliceEngine.slice import SliceEngine
from src.avd.helper import binjaWrapper


class ArgParseMock(object):
    """
    Mocking argparse
    """
    def __init__(self, deep, fast):
        self.deep = deep
        self.fast = fast


class TestSliceEngine(unittest.TestCase):

    def setUp(self):
        self._plugins = PluginLoader()

    def test_slice_engine_1(self):
        """
        Testcase to test the slice engine to work properly
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./SliceEngine/Test1/slice.bndb")
        symbol = bv.get_symbol_by_raw_name("memcpy")
        args = ArgParseMock(False, False)
        if symbol is not None:
            for ref in bv.get_code_refs(symbol.address):
                instr = binjaWrapper.get_medium_il_instruction(bv, ref.address)
                dest_var = binjaWrapper.get_ssa_var_from_mlil_instruction(instr, 0)
                slice_class = SliceEngine(args=args, bv=bv)
                visited_instructions = slice_class.do_backward_slice_with_variable(
                    instr,
                    binjaWrapper.get_mlil_function(bv, ref.address).ssa_form,
                    dest_var,
                    list()
                )
                print(visited_instructions)


if __name__ == '__main__':
    unittest.main()
