import unittest
import binaryninja

from src.avd.loader import PluginLoader


class TestBufferOverflows(unittest.TestCase):

    def setUp(self):
        self._plugins = PluginLoader()


    def test_buffer_overflow_1(self):
        """
        Testcase to find vuln if dest and source size are known but n is <undertermined>
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test1/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.vulns = []
        plugin.run(bv, False)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x829, addresses), 'Could not find the Bug'
        self.assertGreater(highprob, 89), 'Found the initial one but could not follow to get the source'

    def test_buffer_overflow_2(self):
        """
        Testcase to find vuln for N is bigger than destination size
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test2/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.vulns = []
        plugin.run(bv, False)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x825, addresses), 'Could not find the Bug'
        self.assertGreater(highprob, 90), 'Could not find the bug'

    def test_buffer_overflow_3(self):
        """
        Testcase to find 2 Vulnerabilities same as in Testcase "test_buffer_overflow_2" where N is bigger than
        Destination Size.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test3/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.vulns = []
        plugin.run(bv, False)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob
            self.assertGreater(highprob, 90), 'All Vulnerabilities here should be higher than 90'

        self.assertIn(0x825, addresses), 'Could not find the Bug'
        self.assertIn(0x807, addresses), 'Could not find the Bug'


    def test_buffer_overflow_4(self):
        """
        Testcase to find occurances of gets and fgets with only a single Variable as destination Buffer
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test4/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.vulns = []
        plugin.run(bv, False)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x715, addresses), 'Could not find the Bug'
        self.assertGreater(highprob, 90), 'All Vulnerabilities here should be higher than 90'

    def test_buffer_overflow_5(self):
        """
        Testcase to find Compiler optimized Memory Copy functions It will also test if the destination is smaller
        than the source
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test5/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.vulns = []
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x76f, addresses), 'Could not find the Bug'
        self.assertGreater(highprob, 79), 'Could not follow to find the source'

    def test_buffer_overflow_6(self):
        """
        Testcase to find two Vulnerabilities. One in fgets and one in strcpy
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test6/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.vulns = []
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x7e7, addresses), 'Could not find the fgets Bug'
        self.assertIn(0x800, addresses), 'Could not find the strcpy Bug'
        self.assertGreater(highprob, 79), 'Could not follow to find the source'

    def test_buffer_overflow_7(self):
        """
        Testcase to find two Vulnerabilities. One in fgets and one in strcpy
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test7/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.vulns = []
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x7f7, addresses), 'Could not find the fgets Bug'
        self.assertIn(0x815, addresses), 'Could not find the strncpy Bug'
        self.assertGreater(highprob, 79), 'Could not follow to find the source'

    def test_buffer_overflow_8(self):
        """
        Testcase to find two Vulnerabilities. One in fgets and one in strcpy
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test8/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.vulns = []
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x800, addresses), 'Could not find the strncpy Bug'
        self.assertGreater(highprob, 79), 'Could not follow to find the source'

    def test_buffer_overflow_9(self):
        """
        Testcase to find two Vulnerabilities. One in fgets and one in strcpy
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test9/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.vulns = []
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x809, addresses), 'Could not find the sprintf Bug'
        self.assertIn(0x7e7, addresses), 'Could not find the sprintf Bug'
        self.assertGreater(highprob, 60), 'Could not follow to find the source'

    def test_buffer_overflow_10(self):
        """
        Testcase to find no Vulnerabilities.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test10/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob
        self.assertFalse(bool(addresses)), 'Found bugs where no bugs are'

    def test_buffer_overflow_11(self):
        """
        Testcase to find one Vulnerability in scanf.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test11/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x754, addresses), 'Could not find the scanf Bug'
        self.assertGreater(highprob, 60), 'Could not follow to find the source'

    def test_buffer_overflow_12(self):
        """
        Testcase to find a scanf Vulnerability.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test12/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x754, addresses), 'Could not find the scanf Bug'
        self.assertGreater(highprob, 60), 'Could not follow to find the source'

    def test_buffer_overflow_12(self):
        """
        Testcase to find two scanf Vulnerabilities.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/Test13/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x754, addresses), 'Could not find the first scanf Bug'
        self.assertIn(0x76c, addresses), 'Could not find the second scanf Bug'
        self.assertGreater(highprob, 60), 'Could not follow to find the source'

    def test_buffer_overflow_13(self):
        """
        Testcase to find an often occurring memcpy pattern.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./bin/TestMcpy/bo")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x7cc, addresses), 'Could not find the first scanf Bug'
        self.assertGreater(highprob, 79), 'Could not follow to find the source'

    def CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01(self):
        """
        @description
        CWE: 121 Stack Based Buffer Overflow
        Sinks: type_overrun_memcpy
            GoodSink: Perform the memcpy() and prevent overwriting part of the structure
            BadSink : Overwrite part of the structure by incorrectly using the sizeof(struct) in memcpy()
        Flow Variant: 01 Baseline
        Testcase to find an often occurring memcpy pattern.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/CWE121_Stack_Based_Buffer_Overflow/s01/"
                                                         "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_"
                                                         "memcpy_01.out")
        plugin = self._plugins.get_plugin_instance('PluginBufferOverflow')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xd22, addresses), 'Could not find the memcpy Bug'
        self.assertGreater(highprob, 79), 'Could not follow to find the source'

    def test_uninitialized_variable_01(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_01.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_02(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_02.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_03(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_03.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_04(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_04.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_05(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_05.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_06(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_06.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_07(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_07.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_08(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_08.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_09(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_09.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_10(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_10.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_11(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_11.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_12(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_12.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_13(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_13.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_15(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_15.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_uninitialized_variable_17(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./juliet/"
                                                         "CWE457_Use_of_Uninitialized_Variable/s01/"
                                                         "CWE457_Use_of_Uninitialized_Variable__char_pointer_17.out")
        plugin = self._plugins.get_plugin_instance('PluginUninitializedVariable')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginUninitializedVariable'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0xc98, addresses), 'Could not find the Uninitialized Variable'

    def test_signed_problem_malloc(self):
        """
        Testcase to find an uninitialized variable.
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file(
            "juliet/"
            "CWE195_Signed_to_Unsigned_Conversion_error/s01/"
            "CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_malloc_01.out"
        )
        plugin = self._plugins.get_plugin_instance('PluginSignedAnalysis')
        self.assertIsNotNone(plugin), 'Could not load Plugin PluginSignedAnalysis'
        plugin.run(bv, deep=True)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x100f, addresses), 'Could not find the malloc Problem'

if __name__ == '__main__':
    unittest.main()