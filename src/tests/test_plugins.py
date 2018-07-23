import unittest
import binaryninja


from avd.loader import PluginLoader

class TestTransformers(unittest.TestCase):
    def setUp(self):
        self._plugins = PluginLoader()

    def test_buffer_overflow_1(self):
        """
        Testcase to find vuln if dest and source size are known but n is <undertermined>
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./tests/bin/Test1/bo")
        plugin = self._plugins.get_plugin_instance('bo')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
        plugin.run(bv, False)
        self.assertIsNone(plugin.error), 'An error occurred'
        addresses = []
        highprob = 0
        for vuln in plugin.vulns:
            addresses.append(vuln.instr.address)
            highprob = vuln.probability if vuln.probability > highprob else highprob

        self.assertIn(0x829, addresses), 'Could not find the Bug'
        self.assertGreater(highprob, 90), 'Found the initial one but could not follow to get the source'

    def test_buffer_overflow_2(self):
        """
        Testcase to find vuln for N is bigger than destination size
        :return:
        """
        bv = binaryninja.BinaryViewType.get_view_of_file("./tests/bin/Test2/bo")
        plugin = self._plugins.get_plugin_instance('bo')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
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
        bv = binaryninja.BinaryViewType.get_view_of_file("./tests/bin/Test3/bo")
        plugin = self._plugins.get_plugin_instance('bo')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
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
        bv = binaryninja.BinaryViewType.get_view_of_file("./tests/bin/Test4/bo")
        plugin = self._plugins.get_plugin_instance('bo')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
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
        bv = binaryninja.BinaryViewType.get_view_of_file("./tests/bin/Test5/bo")
        plugin = self._plugins.get_plugin_instance('bo')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
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
        bv = binaryninja.BinaryViewType.get_view_of_file("./tests/bin/Test6/bo")
        plugin = self._plugins.get_plugin_instance('bo')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
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
        bv = binaryninja.BinaryViewType.get_view_of_file("./tests/bin/Test7/bo")
        plugin = self._plugins.get_plugin_instance('bo')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
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
        bv = binaryninja.BinaryViewType.get_view_of_file("./tests/bin/Test8/bo")
        plugin = self._plugins.get_plugin_instance('bo')
        self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
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
        def test_buffer_overflow_7(self):
            """
            Testcase to find two Vulnerabilities. One in fgets and one in strcpy
            :return:
            """
            bv = binaryninja.BinaryViewType.get_view_of_file("./tests/bin/Test9/bo")
            plugin = self._plugins.get_plugin_instance('bo')
            self.assertIsNotNone(plugin), 'Could not load Plugin Buffer Overflow'
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

if __name__ == '__main__':
    unittest.main()