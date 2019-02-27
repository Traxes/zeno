import unittest
import binaryninja

from src.avd.loader import PluginLoader
from src.avd.core.sliceEngine import slice
from src.avd.helper import binjaWrapper

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
        if symbol is not None:
            for ref in bv.get_code_refs(symbol.address):
                instr = binjaWrapper.get_medium_il_instruction(bv, ref.address)
                dest_var = binjaWrapper.get_ssa_var_from_mlil_instruction(instr, 0)
                visited_instructions = slice.do_backward_slice_with_variable(
                    instr,
                    binjaWrapper.get_mlil_function(bv, ref.address).ssa_form,
                    dest_var
                )
                print(visited_instructions)






        #plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        #self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        #plugin.vulns = []
        #plugin.run(bv, False)
        #self.assertIsNone(plugin.error), 'An error occurred'
        #addresses = []
        #highprob = 0
        #for vuln in plugin.vulns:
        #    addresses.append(vuln.instr.address)
        #    highprob = vuln.probability if vuln.probability > highprob else highprob

        #self.assertIn(0x829, addresses), 'Could not find the Bug'
        #self.assertGreater(highprob, 89), 'Found the initial one but could not follow to get the source'


if __name__ == '__main__':
    unittest.main()