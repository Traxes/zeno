from src.avd.plugins import Plugin
from src.avd.reporter.vulnerability import Vulnerability
from binaryninja import MediumLevelILOperation
from tqdm import tqdm


class PluginSignedAnalysis(Plugin):
    name = "SignedAnalysis"
    display_name = "SignedAnalysis"
    cmd_name = "SignedAnalysis"
    cmd_help = "Find problems with signed/unsinged numbers"

    # It would be awesome to keep updating this list
    unsigned_sinks = dict(
        malloc=0,
        memcpy=2,
        read=2,
        pread=2,
        memmove=2,
        strncpy=2
    )

    def __init__(self, bv=None):
        """
        Constructor
        :param bv:
        """
        super(PluginSignedAnalysis, self).__init__(bv)
        self.bv = bv

    def set_bv(self, bv):
        """
        Settter for the BinaryView
        :param bv:
        :return:
        """
        self.bv = bv

    def run(self, bv=None, args=None, traces=None):
        """
        Run Function (Required)
        :param bv:
        :param args:
        :param traces:
        :return:
        """
        super(PluginSignedAnalysis, self).__init__(bv)
        for funcs in tqdm(self.bv.functions, desc=self.name, leave=False):
            self._function_sign_analysis_start(funcs)
        return

    def _function_sign_analysis_start(self, func):
        """
        Finding conversions problems to size_t sinks
        :param func:
        :return:
        """
        for blocks in func.medium_level_il:
            for instr in blocks:
                if instr.operation == MediumLevelILOperation.MLIL_CALL:
                    try:
                        call_name = self.bv.get_function_at(instr.dest.constant).name
                    except AttributeError:
                        # Bypass GOT references...
                        continue

                    if call_name in self.unsigned_sinks.keys():
                        try:
                            if instr.vars_read[self.unsigned_sinks.get(call_name)].type.signed:
                                text = "MLIL {} 0x{:x}\n".format(func.name, instr.address)
                                text += "\t\tPotential bad sign conversion\n"
                                text += "\t\t\tVariable {} is signed but will be implicitly" \
                                        " converted by {} to size_t\n".format(
                                    instr.vars_read[self.unsigned_sinks.get(call_name)],
                                    call_name
                                )

                                vuln = Vulnerability("Potential signedness problem!",
                                                     text,
                                                     instr,
                                                     "It appears that signed variable is converted by an implicit "
                                                     "conversion with a function call.",
                                                     60)
                                self.vulns.append(vuln)

                        except IndexError:
                            # Sometimes there are static values to the function call... bypassing it
                            continue
