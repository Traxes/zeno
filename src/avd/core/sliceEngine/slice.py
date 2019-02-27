# Credits: Josh Watson @joshwatson for slicing
from binaryninja import SSAVariable, Variable, MediumLevelILOperation
from src.avd.helper import binjaWrapper


# TODO Make forward slice to visit through non blacklisted functions
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


def handle_backward_slice_function(func, index):
    """
    TODO
    :param func:
    :param index:
    :return:
    """
    for ref in func.source_function.view.get_code_refs(func.source_function.start):
        previous_function = func.source_function.view.get_function_at(ref.function.start).medium_level_il
        calling_instr = previous_function[previous_function.get_instruction_start(ref.address)]
        new_slice_variable = calling_instr.ssa_form.vars_read[index]
        return do_backward_slice_with_variable(calling_instr, previous_function.ssa_form, new_slice_variable)


def get_sources_of_variable(bv, var):
    # TODO Recreate this function.. it´s ugly
    if not var:
        return []
    if isinstance(var, SSAVariable):
        var = var.var
    sources = []
    for bb in var.function.medium_level_il.ssa_form:
        for instr in bb:
            for v in (instr.vars_read + instr.vars_written):
                if isinstance(v, Variable):
                    if v.identifier == var.identifier:
                        visited = do_forward_slice(instr, v.function.medium_level_il.ssa_form)
                        for index in visited:
                            call = v.function.medium_level_il.ssa_form[index]
                            if call.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                                if hasattr(call.dest, "constant"):
                                    sources.append(bv.get_symbol_at(call.dest.constant).name)
                                else:
                                    # TODO Relative Call.. skip until implemented
                                    pass
                                # Resolv call.dest
    return sources


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


def get_manual_var_uses_custom_bb(bb_paths, var):
    """
    TODO
    :param bb_paths:
    :param var:
    :return:
    """
    variables = []
    for bb in bb_paths:
        for instr in bb:
            for v in (instr.vars_read + instr.vars_written):
                if v.identifier == var.identifier:
                    variables.append(instr.instr_index)
    return variables


def get_sources(bv, ref, instr, n):
    """
    TODO
    :param bv:
    :param ref:
    :param instr:
    :param n:
    :return:
    """
    slice_src, visited_src = do_backward_slice_with_variable(
        instr,
        binjaWrapper.get_mlil_function(bv, ref.address),
        binjaWrapper.get_ssa_var_from_mlil_instruction(instr, n)
    )

    return get_sources_of_variable(bv, slice_src)


def get_sources_with_mlil_function(bv, func, instr, n):
    """
    TODO
    :param bv:
    :param func:
    :param instr:
    :param n:
    :return:
    """
    slice_src, visited_src = do_backward_slice_with_variable(
        instr,
        func.medium_level_il,
        binjaWrapper.get_ssa_var_from_mlil_instruction(instr, n)
    )

    return get_sources_of_variable(bv, slice_src)


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
    mlil_function[mlil_function.get_ssa_var_definition(ssa_var)]


def do_backward_slice_with_variable(instruction, func, variable):
    """
    TODO
    :param instruction:
    :param func: in MLIL SSA Form:
    :param variable: the Variable to trace:
    :return:
    """

    instruction_queue = {}

    if variable.var.name:
        instruction_queue.update({func.ssa_form.get_ssa_var_definition(variable): variable})

    visited_instructions = [(instruction.ssa_form.instr_index, None)]

    while instruction_queue:

        visit_index = instruction_queue.popitem()

        if visit_index is None or visit_index in visited_instructions:
            continue

        instruction_to_visit = func[visit_index[0]]

        if instruction_to_visit is None:
            continue

        for var in instruction_to_visit.ssa_form.vars_read:
            if type(var) is not SSAVariable:
                # TODO Sometimes BN cannot assign it to SSA_FORM...
                continue
            if var.var.name:
                if func.ssa_form.get_ssa_var_definition(var) is not None:
                    instruction_queue.update({func.ssa_form.get_ssa_var_definition(var): var})
                else:
                    var, slice_visited_instructions = handle_backward_slice_function(func, var.var.index)
                    visited_instructions += slice_visited_instructions

        visited_instructions.append(visit_index)

    return var, visited_instructions
