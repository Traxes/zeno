from graph import *


class InsAnalysis:
    """
    A meta-instruction which we do analysis over
    """
    def __init__ (self, basic_block, bb_index, il):
        """
        Constructor for InsAnalysis
        @param basic_block The BBAnalysis this InsAnalysis belongs to.
        @param bb_index The index in BBAnalysis of this instruction.
        """
        self.basic_block = basic_block
        self.bb_index = bb_index
        self.il = il
        self.written = {}
        self.read = {}

    def apply_ssa(self, in_variables):
        """
        Takes a dict of identifiers to VariableAnalysis instances, and returns
        a dict of identifiers to VariableAnalysis instances of variables which
        are modified by in_variables.
        @param in_variables a dict of variable identifiers to VariableAnalysis
                            which are valid before this instruction is executed.
        @return A dict of identifiers to VariableAnalysis instances, which are
                the state of all variables after this instruction. I.E. this is
                in_variables with identifiers that were written replaced with
                their new VariableAnalysis instances.
        """

        # Get an instance of our SSA creator
        ssa = getSSA()

        written, read = il_registers(self.il)

        print written, read, self.il, self.il.operation

        # We don't want to modify the in_variables we were given. We can now
        # changes this up at will.
        in_variables = copy.deepcopy(in_variables)

        # We need to first go through read registers, and see if they are in
        # our in_variables. If not, we add those.
        for r in read:
            # If this read variable doesn't exist, create it and give it a
            # unique SSA identifier
            if r not in in_variables:
                self.read[r] = VariableAnalysis(r, ssa.new_ssa(r))
            else:
                self.read[r] = copy.deepcopy(in_variables[r])

        # No we go through written variables, and apply SSA to them
        written_ = {}
        for w in written:
            ww = VariableAnalysis(w, ssa.new_ssa(w))
            written_[w] = ww

        # and we apply all of our read registers to our written registers
        for w in written_:
            for r in self.read:
                written_[w].dependencies.append(copy.deepcopy(r))

        # save our written registers
        self.written = copy.deepcopy(written_)

        # now overwrite values in in_variables to create our result
        # written_ shouldn't have any references anywhere and should be a pure
        # copy.
        for w in written_:
            in_variables[w.identifier] = w

        return in_variables # in is the new out


class BBAnalysis:
    """
    This is a wrapper around a binary ninja basic block. We use this to track
    analysis around this block when creating a vertex in our graph.
    """
    def __init__(self, basic_block):
        self.basic_block = basic_block
        self.instructions = []
        for i in range(len(self.basic_block)) :
            self.instructions.append(InsAnalysis(self, i, self.basic_block[i]))

    def print_il_instructions(self):
        for ins in self.basic_block:
            print ins.operation, ins

    def read_written_registers(self):
        written_ = []
        read_ = []
        for il in self.basic_block:
            written, read = il_registers(il)
            print written, read
            for r in read:
                if r not in written_:
                    read_.append(r)
            for w in written:
                written_.append(w)
        return read_, written_

    def apply_ssa(self, in_variables):
        variables = in_variables
        for i in range(len(self.basic_block)):
            out_variables = self.instructions[i].apply_ssa(variables)
            for k in out_variables:
                variables[k] = out_variables[k]
        return variables


def graph_function(func):
    graph = Graph(0)

    # get the low_level_il basic blocks
    basic_blocks = func.medium_level_il.basic_blocks

    # We are going to add each basic block to our graph
    for basic_block in basic_blocks:
        graph.add_vertex(basic_block.start, BBAnalysis(basic_block))

    # Now we are going to add all the edges
    for basic_block in basic_blocks:
        for outgoing_edge in basic_block.outgoing_edges:
            target = outgoing_edge.target
            graph.add_edge_by_indices(basic_block.start, target.start, None)

    # Now return the graph
    return graph


def loop_analysis(bb):
    graph = graph_function(bb.function)
    loops = graph.detect_loops()
    for loop in loops:
        if bb.start in loop:
            return True

