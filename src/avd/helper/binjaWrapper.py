"""
These helper functions are usually one liner. Those conversions are usually not (yet) very well documented
and thus, I do not forget them again :).
"""
import codecs


def get_low_il_instruction(bv, addr):
    """
    This helper function will return the vulnurable low level il Instruction
    :param addr:
    :return:
    """
    # TODO check if this breaks with ARM or Mips !
    return bv.arch.get_instruction_low_level_il_instruction(bv, addr)


def get_medium_il_instruction(bv, addr):
    # Assuming that there is only one matching function for the given address.
    mff = bv.get_functions_containing(addr)[0].medium_level_il
    return mff[mff.get_instruction_start(addr)]


def get_ssa_var_from_mlil_instruction(instr, i):
    return instr.ssa_form.vars_read[i]


def get_mlil_function(bv, addr):
    # Assuming that there is only one matching function for the given address.
    return bv.get_functions_containing(addr)[0].medium_level_il

def get_basic_block_from_instr(bv, addr):
    try:
        bb = bv.get_basic_blocks_at(addr)[0]
        return bb
    except IndexError:
        return None

def get_constant_string(bv, addr):
    """
    Returns the full string in memory
    :param bv: the BinaryView:
    :param addr: Address where the string is:
    :return string:
    """
    str_len = 0
    curr = codecs.encode(bv.read(addr, 1), "hex").decode()
    while (curr != "2e") and (curr != "00"):
        str_len += 1
        curr = codecs.encode(bv.read(addr + str_len, 1), "hex").decode()
    return bv.read(addr, str_len).decode()
