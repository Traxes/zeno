from .. import Plugin
from ...reporter.vulnerability import Vulnerability
from ...helper import binjaWrapper, sources
from src.avd.core.sliceEngine import slice
from src.avd.core.sliceEngine.loopDetection import loop_analysis
from binaryninja import MediumLevelILOperation, RegisterValueType

__all__ = ['PluginBufferOverflow']


class BoParams(object):
    def __init__(self, dst = None, src = None, n = None, format = None):
        if dst is not None:
            self.dst = dst
        if src is not None:
            self.src = src
        if n is not None:
            self.n = n
        if format is not None:
            self.Format = format


class fake_register(object):
    def __init__(self, name, constant=False):
        self.name = name
        self.is_constant = constant


def get_params(addr):
    for blocks in addr.function.medium_level_il:
        for instr in blocks:
            if instr.address == addr.address:
                return instr.params


def get_constant_string(bv, addr):
    strLen = 0
    curr = bv.read(addr, 1).encode('hex')
    while (curr != "2e") and (curr != "00"):
        strLen += 1
        curr = bv.read(addr + strLen, 1).encode('hex')
    return bv.read(addr, strLen)

def parse_format_string(s, params):
    string_match = re.findall(r'%[0-9]*[diuoxfegacspn]', s, re.I)
    format_vars = collections.OrderedDict()
    for i, form in enumerate(string_match):
        format_vars[form] = params[i]
    return format_vars


def calc_size(var, func):
    if len(func.stack_layout) - 1 == func.stack_layout.index(var):
        return abs(var.storage)
    else:
        return abs(var.storage) - abs(func.stack_layout[func.stack_layout.index(var) + 1].storage)


# TODO Move to PrettyPrinter Class
def print_f_call(arg):
    arg_iter = iter(arg[:])
    fun_c = next(arg_iter)
    fun_c += "("
    for i, ar in enumerate(arg_iter, 1):
        try:
            fun_c += ar
        except TypeError:
            fun_c += ar.name
        except:
            traceback.print_exc()
        if i < (len(arg)-1):
            fun_c += ', '
    fun_c += ");"
    return fun_c


class PluginBufferOverflow(Plugin):
    name = "bo"
    display_name = "Buffer Overflow"
    cmd_name = "bo"
    cmd_help = "Search for Known Buffer Overflow patterns"


    def __init__(self):
        super(PluginBufferOverflow, self).__init__()
        self.arch_offsets = {
            'armv7':4,
            'x86_64':0,
        }
        self.bo_symbols = {
            "_memcpy":BoParams(dst=0,src=1,n=2),
            "memcpy":BoParams(dst=0,src=1,n=2),
            "_strncpy":BoParams(dst=0,src=1,n=2),
            "strncpy":BoParams(dst=0,src=1,n=2),
            "_strcpy":BoParams(dst=0, src=1),
            "strcpy":BoParams(dst=0, src=1),
            "_strcat":BoParams(dst=0, src=1),
            "strcat":BoParams(dst=0, src=1), ## TODO: strcat Needs to special checked if buffer was filled before!
            "_strncat":BoParams(dst=0, src=1, n=2),
            "strncat":BoParams(dst=0, src=1, n=2),
            "_sprintf":BoParams(dst=0, src=2),
            "sprintf":BoParams(dst=0, src=2), ## TODO: Multiple Args & Calc Length of FormatString
            "_snprintf":BoParams(dst=0, src=3, n=1),
            "snprintf":BoParams(dst=0, src=3, n=1),
            "_vsprintf":BoParams(dst=0, src=2),
            "vsprintf":BoParams(dst=0, src=2),
            "_fgets":BoParams(dst=0, n=1),
            "fgets":BoParams(dst=0, n=1),
            "gets":BoParams(dst=0),
            "_gets":BoParams(dst=0),
            "__isoc99_scanf":BoParams(Format=0),
        }

    # TODO Add default Blacklist to avoid Parsing e.g. libc
    def deep_function_analysis(self, bv):
        for func in bv.functions:
            func_mlil = func.medium_level_il
            for bb in func_mlil:
                for instr in bb:
                    # MLIL Store might be interesting due to Compiler optimizations
                    if instr.operation == MediumLevelILOperation.MLIL_STORE:
                        # Check that Source is not Static # TODO might miss src > dest
                        if instr.src.possible_values.type == RegisterValueType.UndeterminedValue:
                            # Instruction should be in a loop. Otherwise a BoF is unlikely
                            if loop_analysis(bb):
                                # Slice to Source
                                # TODO Currently only works for MLIL_STORE (e.g. <il: [rdi_1].q = [rsi].q>)
                                src, src_visited_instr = slice.do_backward_slice(bv, instr, instr.ssa_form.vars_read[1],
                                                                                 func_mlil.ssa_form)
                                dst, dst_visited_instr = slice.do_backward_slice(bv, instr, instr.ssa_form.vars_read[0],
                                                                                 func_mlil.ssa_form)
                                src_size = calc_size(src, func)
                                dst_size = calc_size(dst, func)
                                if src_size > dst_size:
                                    # Might be an overflow. Lets Check if Source comes from a nasty function.
                                    # pretty print array
                                    cf = ["memcpy"]
                                    cf.append(src)
                                    cf.append(dst)
                                    cf.append("<undetermined>")
                                    text = "{} 0x{:x}\t{}\n".format(func.name,
                                                                    instr.address, print_f_call(cf))
                                    text += "\t\tPotential Overflow!\n"
                                    text += "\t\t\tdst {} = {}\n".format(dst.name, dst_size)
                                    text += "\t\t\tsrc {} = {}\n".format(src.name, src_size)
                                    v = Vulnerability("Potential Overflow",
                                                      text,
                                                      instr,
                                                      "The Source  Size: {} appears to be bigger than the destination Size:"
                                                      " {}".format(calc_size(src, func), calc_size(dst, func)),
                                                      50)
                                    if not func_mlil.get_var_uses(src):
                                        # Probably dealing with a reference. Currently not implemented in BN. Hence.. parsing manually
                                        for n in slice.get_manual_var_uses(func_mlil, src):
                                            if n not in src_visited_instr:
                                                if src in func_mlil[n].vars_read:
                                                    for vs in func_mlil[n].vars_written:
                                                        for ea in slice.do_forward_slice(func_mlil[n], func_mlil):
                                                            if func_mlil[ea].operation == MediumLevelILOperation.MLIL_CALL:
                                                                if bv.get_function_at(func_mlil[ea].dest.constant).name in sources.user_sources:
                                                                    # Check wheter it is in known user input sources Increase Probability
                                                                    v.append_reason(
                                                                        "The Source Location was used by a known Source")
                                                                    v.probability = 80
                                                else:
                                                    # TODO
                                                    # Written
                                                    pass
                                    self.append_vuln(v)


    def run(self, bv, deep=True):
        super(PluginBufferOverflow, self).run(bv)

        if deep:
            self.deep_function_analysis(bv)

        arch_offset = self.arch_offsets[bv.arch.name]
        for syms in self.bo_symbols:
            symbol = bv.get_symbol_by_raw_name(syms)
            if symbol is not None:
                for ref in bv.get_code_refs(symbol.address):
                    function = ref.function
                    addr = ref.address
                    try:
                        bo_src = self.bo_symbols.get(syms).src
                    except AttributeError:
                        bo_src = None
                    except:
                        traceback.print_exc()

                    try:
                        bo_n = self.bo_symbols.get(syms).n
                    except AttributeError:
                        bo_n = None
                        n = None
                    except:
                        traceback.print_exc()

                    try:
                        bo_format = self.bo_symbols.get(syms).format
                    except AttributeError:
                        bo_format = None
                    except:
                        traceback.print_exc()

                    try:
                        bo_dst = self.bo_symbols.get(syms).dst
                    except AttributeError:
                        bo_dst = None
                    except:
                        traceback.print_exc()

                    #print(syms)

                    cf = []
                    cf.append(syms)

                    ## Handling Format Strings like scanf
                    if bo_format is not None:
                        params = []
                        for i in range(0, len(get_params(ref))):
                            params.append(function.get_parameter_at(addr, None, i))
                        format_string = get_constant_string(bv, params[self.bo_symbols.get(syms).format].value)
                        cf.append("'" + format_string + "'")
                        params.pop(bo_format)
                        format_vars = parse_format_string(format_string, params)
                        for f_str in format_vars:
                            v = ref.function.get_stack_var_at_frame_offset(format_vars[f_str].offset, function.start)
                            if "s" in f_str or "c" in f_str:
                                buf = ""
                                try:
                                    ## if This fails there is prob no limitation
                                    size = int(f_str[1:-1])
                                except:
                                    traceback.print_exc()
                                    size = sys.maxsize
                                dst_f_size = calc_size(v, function)
                                if size >= dst_f_size:
                                    ## Pretty Print
                                    buf = "\t\t\033[93mPotential Overflow!\n\t\t\tdst {} = {}\n\t\t\tsrc {} = {}".format(
                                        v.name, dst_f_size, f_str, size)
                                    v = "\033[93m" + v.name + "\033[0m"

                            cf.append(v)

                        print("{} 0x{:x}\t{}\n{}\033[0m\n".format(ref.function.name, addr, print_f_call(cf), buf))
                        continue

                    if bo_dst is not None:
                        dst = function.get_parameter_at(addr, None, self.bo_symbols.get(syms).dst)
                        if 'StackFrameOffset' not in str(dst.type):
                            if hasattr(dst, "value"):
                                dst_var = fake_register("<const>")
                                dst_size = dst.value
                            elif 'UndeterminedValue' in str(dst.type):
                                dst_var = fake_register("<undetermined>")
                                dst_size = 0
                            else:
                                dst_var = fake_register(dst.reg)
                                dst_size = 0
                        else:
                            dst_var = ref.function.get_stack_var_at_frame_offset(dst.offset + arch_offset,
                                                                                 function.start)
                            if dst_var is None:
                                dst_var = ref.function.get_stack_var_at_frame_offset(dst.offset, function.start)
                            dst_size = calc_size(dst_var, function)
                        cf.append(dst_var)

                    if bo_src is None and bo_n is None and bo_format is None:
                        """
                        Handling unsafe uses of gets and fgets while only providing a single variable as destination
                        Buffer
                        """
                        text = "{} 0x{:x}\t{}\n".format(ref.function.name, addr, print_f_call(cf))
                        text += "\t\tPotential Overflow!\n"
                        text += "\t\t\tdst {} = {}\n".format(dst_var.name, dst_size)
                        instr = binjaWrapper.get_medium_il_instruction(bv, ref.address)
                        v = Vulnerability("Potential Overflow",
                                          text,
                                          instr,
                                          "Uses of gets and fgets only passing the"
                                          " destination variable is highly critical",
                                          100)
                        self.vulns.append(v)
                        continue

                    if bo_src is not None:
                        src = function.get_parameter_at(addr, None, self.bo_symbols.get(syms).src)
                        if 'StackFrameOffset' not in str(src.type):
                            if hasattr(src, "value"):
                                src_var = fake_register("<const>")
                                src_size = src.value
                            elif 'UndeterminedValue' in str(src.type):
                                src_var = fake_register("<undetermined>")
                                src_size = 0
                            else:
                                src_var = fake_register(src.reg)
                                src_size = 0
                        else:
                            src_var = ref.function.get_stack_var_at_frame_offset(src.offset + arch_offset,
                                                                                 function.start)
                            if src_var is None:
                                src_var = ref.function.get_stack_var_at_frame_offset(src.offset, function.start)
                            src_size = calc_size(src_var, function)
                        cf.append(src_var)

                    if bo_n is not None:
                        n = function.get_parameter_at(addr, None, self.bo_symbols.get(syms).n)
                        if 'StackFrameOffset' not in str(n.type) and 'ConstantValue' not in str(n.type):
                            try:
                                if hasattr(n, "reg"):
                                    n = fake_register(n.reg, constant=n.reg.is_constant)
                                else:
                                    n_val = "<undetermined>"
                                    n = fake_register("<undetermined>", constant=n.is_constant)
                            except Exception as e:
                                traceback.print_exc()
                                real_param_name = get_params(ref)[bo_n].src.name
                                n = fake_register(real_param_name)
                                n_val = real_param_name
                        else:
                            if n.is_constant:
                                n_val = str(n.value)
                            else:
                                n_val = str(n)
                        cf.append(n_val)

                    # Print the function
                    print("{} 0x{:x}\t{}".format(ref.function.name, addr, print_f_call(cf)))

                    if bo_src is not None and bo_n is None and bo_dst is not None:
                        if src_size > dst_size:
                            """
                            Source Size is Bigger than dst_size
                            """
                            text = "{} 0x{:x}\t{}\n".format(ref.function.name, addr, print_f_call(cf))
                            text += "\t\tPotential Overflow!\n"
                            text += "\t\t\tdst {} = {}\n".format(dst_var.name, dst_size)
                            text += "\t\t\tsrc {} = {}\n".format(src_var.name, src_size)
                            instr = binjaWrapper.get_medium_il_instruction(bv, ref.address)
                            v = Vulnerability("Potential Overflow",
                                              text,
                                              instr,
                                              "The Source Buffer Size is bigger than the destination Buffer", 80)
                            self.vulns.append(v)
                            continue
                    elif bo_src is not None and bo_n is not None:
                        if str(n) == '<undetermined>' or not n.is_constant:
                            """
                            N Value is undermined and source is not known. This will trigger a reverse Slice
                            to find the initiating part and check wether it might be attacker controlled against
                            the sources array 
                            """
                            if (src_size > dst_size):
                                text = "{} 0x{:x}\t{}\n".format(ref.function.name, addr, print_f_call(cf))
                                text += "\t\tPotential Overflow!\n"
                                text += "\t\t\tdst {} = {}\n".format(dst_var.name, dst_size)
                                text += "\t\t\tsrc {} = {}\n".format(src_var.name, src_size)
                                instr = binjaWrapper.get_medium_il_instruction(bv, ref.address)
                                v = Vulnerability("Potential Overflow",
                                                  text,
                                                  instr,
                                                  "The Source Buffer Size is bigger than the destination Buffer", 60)

                                # TODO make a deep search on n for more probability!
                                slice_src, visited_src = slice.do_backward_slice(
                                    bv,
                                    instr,
                                    binjaWrapper.get_ssa_var_from_mlil_instruction(instr, 2),
                                    binjaWrapper.get_mlil_function(bv, ref.address)
                                )
                                for found_source in slice.get_sources_of_variable(bv, slice_src):
                                    if found_source in sources.user_sources:
                                        v.probability = 100
                                        v.append_reason("Might be controllable through the following sources: {}".format(
                                            found_source
                                        ))
                                self.vulns.append(v)
                                continue

                    if bo_n is not None and n.is_constant:
                        # N is constant
                        if n.value > dst_size:
                            """
                            N Value is bigger than dst size. 
                            """
                            text = "{} 0x{:x}\t{}\n".format(ref.function.name, addr, print_f_call(cf))
                            text += "\t\tPotential Overflow!\n"
                            text += "\t\t\tdst {} = {}\n".format(dst_var.name, dst_size)
                            text += "\t\t\tn {} = {}\n".format(str(n), n_val)
                            instr = binjaWrapper.get_medium_il_instruction(bv, ref.address)
                            v = Vulnerability("Potential Overflow",
                                              text,
                                              instr,
                                              "The amount of Copied bytes is bigger than the destination Buffer",
                                              100)
                            self.vulns.append(v)
                        elif n.value == dst_size:
                            """
                            Might indicate a Off-By-One 
                            """
                            # TODO
                            pass
                    if bo_src is not None:
                        if hasattr(src_var, "name") and hasattr(n, "name"):
                            if src_var.name == "<undetermined>" and n.name == "<undetermined>":
                                pass
                                #print("\t\t\033[93mPotential Overflow!")

                    if bo_dst is not None:
                        #pass
                        print("\t\t\tdst {} = {}".format(dst_var.name, dst_size))
                    if bo_src is not None:
                        #pass
                        print("\t\t\tsrc {} = {}".format(src_var.name, src_size))
                    if bo_n is not None and hasattr(n, "name"):
                        #pass
                        print("\t\t\tn = {}".format(n.name))
                    print("\033[0m")

