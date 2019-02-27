from src.avd.plugins import Plugin
from src.avd.reporter.vulnerability import Vulnerability
from src.avd.core.sliceEngine import slice
from binaryninja import MediumLevelILOperation, VariableSourceType
from src.avd.core.sliceEngine.loopDetection import graph_function
from tqdm import tqdm

__all__ = ['PluginUninitializedVariable']


class PluginUninitializedVariable(Plugin):
    name = "UninitializedVariable"
    display_name = "UninitializedVariable"
    cmd_name = "UninitializedVariable"
    cmd_help = "Search for Uninitialized Variables"

    # This Dict will whitelist some functions where variables are initialized
    KnownFunctions = {"__isoc99_sscanf": 1,
                      "__isoc99_swscanf": 1,
                      "pthread_create": 0}

    def __init__(self, bv=None):
        super(PluginUninitializedVariable, self).__init__(bv)
        self.bv = bv

    def set_bv(self, bv):
        self.bv = bv

    def run(self, bv=None, deep=None, traces=None):
        super(PluginUninitializedVariable, self).__init__(bv)
        self._find_uninitialized_variables()
        return


    def check_whitelist(self, mlil_func, occur):
        for ea in slice.do_forward_slice_with_variable(mlil_func[occur], mlil_func.ssa_form):
            if mlil_func.ssa_form[ea[0]].operation == MediumLevelILOperation.MLIL_CALL_SSA:
                if self.bv.get_function_at(
                       mlil_func.ssa_form[ea[0]].dest.constant).name in self.KnownFunctions.keys():
                    vars = mlil_func.ssa_form[ea[0]].vars_read
                    if ea[1] in vars:
                        if vars.index(ea[1]) == self.KnownFunctions[self.bv.get_function_at(mlil_func.ssa_form[ea[0]].dest.constant).name]:
                            return True
                        else:
                            return False
                    return True
        return False

    def check_occurance(self, mlil_func, custom_bb, v):
        for occur in slice.get_manual_var_uses_custom_bb(custom_bb, v):
            if v in mlil_func[occur].vars_written:
                break
            # Return addr usually not written. Bypass it against false positives
            if "__return_addr" == v.name:
                break
            # Filter out Edge cases like Scanff
            if not self.check_whitelist(mlil_func, occur):
                return True
            else:
                return False
        return False



    # Find all possible Paths in the given Graph
    def _find_all_paths(self, graph, start_vertex, end_vertex, path=[]):
        path = path + [start_vertex]
        if start_vertex == end_vertex:
            return [path]
        if not graph.vertices.has_key(start_vertex):
            return []
        paths = []
        for node in graph.get_vertex_from_index(start_vertex).get_successor_indices():
            if node not in path:
                newpaths = self._find_all_paths(graph, node, end_vertex, path)
                for newpath in newpaths:
                    paths.append(newpath)
        return paths




    # Create a Control Flow graph of basic blocks inside a function
    def _create_function_control_flow(self, func):
        # Create Graph
        g = graph_function(func)
        return g.compute_all_paths()

    def _is_in_vulns(self, instr):
        for tmp_vuln in self.vulns:
            if tmp_vuln.instr.address == instr.address:
                return True

        return False

    def _find_uninitialized_variables(self):
        for funcs in tqdm(self.bv.functions):
            control_flow = self._create_function_control_flow(funcs)
            mlil_func = funcs.medium_level_il
            for var in funcs.stack_layout:
                instr_index_array = mlil_func.get_var_uses(var)
                if len(instr_index_array) > 0:
                    for mlil_instr_index in instr_index_array:
                        mlil_instr = mlil_func[mlil_instr_index]
                        for v in mlil_instr.vars_read:
                            if v.source_type == VariableSourceType.StackVariableSourceType:
                                for bb_path in control_flow:
                                    if self.check_occurance(mlil_func, bb_path, v):
                                        instr = mlil_instr
                                        if self._is_in_vulns(instr):
                                            break

                                        text = "MLIL {} 0x{:x}\n".format(funcs.name, mlil_instr.address)
                                        text += "\t\tPotential use of uninitialized variable!\n"
                                        text += "\t\t\tVariable {}\n".format(v.name)
                                        text += "\n\t\tThe following basic block path (MLIL) was taken without " \
                                                "initializing the variable\n"
                                        for bb in bb_path:
                                            text += "\t\t\t{}\n".format(bb)

                                        vuln = Vulnerability("Potential use of uninitialized variable!",
                                                          text,
                                                          instr,
                                                          "A Variable on the Stack appears to be used before initialized.",
                                                          60)
                                        self.vulns.append(vuln)
                                    else:
                                        continue

