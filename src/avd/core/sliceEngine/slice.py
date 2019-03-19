# Credits: Josh Watson @joshwatson for slicing parts
from binaryninja import SSAVariable, Variable, MediumLevelILOperation, MediumLevelILFunction
from src.avd.helper import binjaWrapper
import sys


class SlicedInstruction(object):
    def __init__(self, instr=None, function_index=None, sliced_variable=None, sliced_address=None):
        if instr is not None:
            self.instr = instr
        if function_index is not None:
            self.function_index = function_index
        if sliced_variable is not None:
            self.sliced_variable = sliced_variable
        if sliced_address is not None:
            self.sliced_address = sliced_address


class SliceEngine(object):
    def __init__(self, args=None, bv=None):
        if args is not None:
            self._args = args
        if bv is not None:
            self._bv = bv

    # TODO Make forward slice to visit through non blacklisted functions
    @staticmethod
    def do_forward_slice(instruction, func):
        """
        TODO
        :param instruction:
        :param func:
        :return:
        """
        # if no variables written, return the empty set.
        if not instruction.ssa_form.vars_written:
            return set()

        instruction_queue = {
            use for var in instruction.ssa_form.vars_written if var.var.name
            for use in func.ssa_form.get_ssa_var_uses(var)
        }

        visited_instructions = {instruction.ssa_form.instr_index}

        while instruction_queue:
            visit_index = instruction_queue.pop()

            if visit_index is None or visit_index in visited_instructions:
                continue

            instruction_to_visit = func[visit_index]

            if instruction_to_visit is None:
                continue

            instruction_queue.update(
                (
                    use for var in instruction_to_visit.ssa_form.vars_written
                    if var.var.name
                    for use in func.ssa_form.get_ssa_var_uses(var)
                )
            )

            visited_instructions.add(visit_index)

        return visited_instructions

    # TODO Rework a new function to filter for single variables hitting functions
    @staticmethod
    def do_forward_slice_with_variable(instruction, function):
        """
        TODO
        :param instruction:
        :param function:
        :return:
        """
        # if no variables written, return the empty set.
        if not instruction.ssa_form.vars_written:
            return set()

        instruction_queue = {}

        for var in instruction.ssa_form.vars_written:
            if var.var.name:
                for use in function.ssa_form.get_ssa_var_uses(var):
                    instruction_queue.update({use: var})

        visited_instructions = [(instruction.ssa_form.instr_index, None)]

        while instruction_queue:

            visit_index = instruction_queue.popitem()

            if visit_index is None or visit_index[0] in visited_instructions:
                continue

            instruction_to_visit = function[visit_index[0]]

            if instruction_to_visit is None:
                continue

            for var in instruction_to_visit.ssa_form.vars_written:
                if var.var.name:
                    for use in function.ssa_form.get_ssa_var_uses(var):
                        instruction_queue.update({use: var})

            visited_instructions.append(visit_index)

        return visited_instructions

    def handle_backward_slice_function_fast(self, func, index):
        """
        Fast Function for Faster Progress
        :param func:
        :param index:
        :return:
        """
        for ref in func.source_function.view.get_code_refs(func.source_function.start):
            previous_function = func.source_function.view.get_function_at(ref.function.start).medium_level_il
            calling_instr = previous_function[previous_function.get_instruction_start(ref.address)]
            new_slice_variable = calling_instr.ssa_form.vars_read[index]
            return self.do_backward_slice_with_variable(calling_instr, previous_function.ssa_form, new_slice_variable)

    def handle_backward_slice_function(self, func, index, recursion_limit):
        if self._args.fast:
            return self.handle_backward_slice_function_fast(func, index)
        else:
            return self.handle_backward_slice_function_precise(func, index, recursion_limit)

    def handle_backward_slice_function_precise(self, func, index, recursion_limit):
        """
        Throughout function
        :param func:
        :param index:
        :param recursion_limit:
        :return:
        """
        visited_instructions = list()
        for ref in func.source_function.view.get_code_refs(func.source_function.start):
        #for ref in func.source_function.view.get_code_refs(func.current_address):
            # Avoid referencing the same variable from the function
            if (ref.function.start, index) in recursion_limit:
                continue
            if ref.function.start == func.current_address:
                # If its referencing itself we skip it
                continue
            recursion_limit.append((ref.function.start, index))
            calling_instr = binjaWrapper.get_medium_il_instruction(self._bv, ref.address)
            #previous_functions = self._bv.get_code_refs(
            #    binjaWrapper.get_mlil_function(self._bv, ref.function.start).source_function.start
            #)
            #for previous_function in previous_functions:
                #previous_function = previous_function.function.medium_level_il
                #previous_function = func.source_function.view.get_function_at(ref.function.start).medium_level_il
            #calling_instr = previous_function[previous_function.get_instruction_start(ref.address)]
            # Skip if this was already sliced
            # TODO Remove all Hex occurances
            list_of_addresses = [(x.sliced_address, x.function_index) for x in visited_instructions]
            if (hex(calling_instr.address), calling_instr.instr_index) in list_of_addresses:
                continue
            if not calling_instr.ssa_form.vars_read:
                continue
            new_slice_variable = calling_instr.ssa_form.vars_read[index]
            visited_instructions += self.do_backward_slice_with_variable(calling_instr, calling_instr.function.ssa_form, new_slice_variable, recursion_limit)
        return visited_instructions

    def get_sources_of_variable(self, bv, var):
        # TODO Recreate this function.. it´s ugly
        if not var:
            return []
        if isinstance(var, SSAVariable):
            var = var.var
        sources = []
        if "arg" in var.name:
            sources.append(var.function.name)
        if isinstance(var.function, MediumLevelILFunction):
            func = var.function.ssa_form
        else:
            func = var.function.medium_level_il.ssa_form
        for bb in func:
            for instr in bb:
                for v in (instr.vars_read + instr.vars_written):
                    if isinstance(v, Variable):
                        if v.identifier == var.identifier:
                            visited = self.do_forward_slice(instr, v.function.medium_level_il.ssa_form)
                            for index in visited:
                                call = v.function.medium_level_il.ssa_form[index]
                                if call.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                                    if hasattr(call.dest, "constant"):
                                        if bv.get_symbol_at(call.dest.constant):
                                            sources.append(bv.get_symbol_at(call.dest.constant).name)
                                        else:
                                            sources.append("sub_" + hex(call.dest.constant))
                                    else:
                                        # TODO Relative Call.. skip until implemented
                                        pass
                                    # Resolv call.dest
        return sources

    @staticmethod
    def get_ssa_manual_var_uses(func, var):
        """
        TODO
        :param func:
        :param var:
        :return:
        """
        variables = []
        for bb in func:
            for instr in bb:
                for v in (instr.vars_read + instr.vars_written):
                    if v.identifier == var.identifier:
                        variables.append(instr.instr_index)
        return variables

    @staticmethod
    def get_manual_var_uses(func, var):
        """
        TODO
        :param func:
        :param var:
        :return:
        """
        variables = []
        for bb in func:
            for instr in bb:
                for v in (instr.vars_read + instr.vars_written):
                    if v.identifier == var.identifier:
                        variables.append(instr.instr_index)
        return variables

    @staticmethod
    def get_manual_var_uses_custom_bb(bb_paths, var):
        """
        TODO implement only bb paths
        :param bb_paths:
        :param var:
        :return:
        """
        return var.function.medium_level_il.get_var_definitions(var) + var.function.medium_level_il.get_var_uses(var)

    def get_sources(self, bv, ref, instr, n):
        """
        TODO
        :param bv:
        :param ref:
        :param instr:
        :param n:
        :return:
        """
        visited_src = self.do_backward_slice_with_variable(
            instr,
            binjaWrapper.get_mlil_function(bv, ref.address).ssa_form,
            binjaWrapper.get_ssa_var_from_mlil_instruction(instr, n),
            list()
        )
        possible_sources = list()
        for sources in visited_src:
            possible_sources += self.get_sources_of_variable(bv, sources.sliced_variable)
        return list(set(possible_sources))

    def get_sources2(self, bv, instr, var):
        visited_src = self.do_backward_slice_with_variable(
            instr,
            var.var.function.medium_level_il.ssa_form,
            var,
            list()
        )
        possible_sources = list()
        for sources in visited_src:
            possible_sources += self.get_sources_of_variable(bv, sources.sliced_variable)
        return list(set(possible_sources))

    def get_sources_with_mlil_function(self, bv, func, instr, n):
        """
        TODO
        :param bv:
        :param func:
        :param instr:
        :param n:
        :return:
        """
        slice_src, visited_src = self.do_backward_slice_with_variable(
            instr,
            func.medium_level_il,
            binjaWrapper.get_ssa_var_from_mlil_instruction(instr, n)
        )

        return self.get_sources_of_variable(bv, slice_src)

    @staticmethod
    def get_var_from_register(bv, instr, n):
        """
        TODO
        :param bv:
        :param instr:
        :param n:
        :return:
        """
        mlil_function = binjaWrapper.get_mlil_function(bv, instr.address)
        ssa_var = instr.ssa_form.vars_read[n]
        return mlil_function[mlil_function.get_ssa_var_definition(ssa_var)]

    def do_backward_slice_with_variable(self, instruction, func, variable, recursion_limit):
        """
        TODO
        :param instruction:
        :param func: in MLIL SSA Form:
        :param variable: the Variable to trace:
        :return:
        """
        if not isinstance(variable, SSAVariable):
            # Bail out if no SSA Var
            return list()
        instruction_queue = list()
        first_instruction = SlicedInstruction(
            instruction.ssa_form,
            instruction.ssa_form.instr_index,
            variable,
            hex(instruction.ssa_form.address)
        )
        if variable.var.name:
            instruction_queue.append(first_instruction)

        visited_instructions = [first_instruction]

        while instruction_queue:

            visit_index = instruction_queue.pop()

            if visit_index is None or len(
                    [x for x in visited_instructions if x.function_index != visit_index.function_index]) < 0:
                continue

            instruction_to_visit = func[visit_index.function_index]

            if instruction_to_visit is None:
                continue

            # Special Case for a edge case in BN
            vars = list()
            if instruction_to_visit.operation == MediumLevelILOperation.MLIL_STORE_SSA:
                if variable in instruction_to_visit.vars_read:
                    if instruction_to_visit.vars_read.index(variable):
                        vars = instruction_to_visit.src.vars_read
                    else:
                        vars = instruction_to_visit.dest.vars_read
                else:
                    vars = instruction_to_visit.ssa_form.vars_read
            else:
                vars = instruction_to_visit.ssa_form.vars_read

            for var in vars:
                if type(var) is not SSAVariable:
                    if len([x for x in visited_instructions if x.sliced_address != hex(instruction_to_visit.address)
                                                               or x.function_index != instruction_to_visit.instr_index]) > 0:
                        visited_instructions.append(SlicedInstruction(
                            instruction_to_visit.ssa_form,
                            instruction_to_visit.ssa_form.instr_index,
                            var,
                            hex(instruction_to_visit.ssa_form.address)
                        ))
                    continue
                if var.var.name:
                    if func.ssa_form.get_ssa_var_definition(var) is not None:
                        tmp_instr = func[func.ssa_form.get_ssa_var_definition(var)]
                        list_of_addresses = [(x.sliced_address, x.function_index) for x in visited_instructions]
                        if (hex(tmp_instr.address), tmp_instr.instr_index) not in list_of_addresses:
                            instruction_queue.append(
                                SlicedInstruction(
                                    tmp_instr,
                                    func.ssa_form.get_ssa_var_definition(var),
                                    var,
                                    hex(tmp_instr.address)
                                )
                            )
                    else:
                        # Traverse Functions Backwards
                        if len([x for x in visited_instructions if x.sliced_address != hex(instruction_to_visit.address)
                                                                   or x.function_index != instruction_to_visit.instr_index]) > 0:
                            visited_instructions.append(SlicedInstruction(
                                instruction_to_visit.ssa_form,
                                instruction_to_visit.ssa_form.instr_index,
                                var,
                                hex(instruction_to_visit.ssa_form.address)
                            ))
                        # Prevent multiple entries
                        list_of_addresses = [(x.sliced_address, x.function_index) for x in visited_instructions]
                        for sliced in self.handle_backward_slice_function(func, var.var.index, recursion_limit):
                            if (sliced.sliced_address, sliced.function_index) not in list_of_addresses:
                                visited_instructions.append(sliced)

            if len([x for x in visited_instructions if x.sliced_address != visit_index.sliced_address
                                                       or x.function_index != visit_index.function_index]) > 0:
                visited_instructions.append(visit_index)

        return visited_instructions
