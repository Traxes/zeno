import copy
import sys
# TODO Strip down to only important parts

def set_intersection (sets) :
    '''
    Takes a list of lists, and returns the intersection of those lists.
    '''
    if len(sets) < 1 :
        return sets
    intersection = copy.deepcopy(sets[0])
    for s in sets :
        i = 0
        while i < len(intersection) :
            if intersection[i] not in s :
                del intersection[i]
            else :
                i = i + 1
    return intersection


def set_equivalence (sets) :
    '''
    Takes a list of lists, and returns True if all lists are equivalent, False
    otherwise.
    '''
    # An empty set is equivalent
    if len(sets) < 0 :
        return True
    # Sets of differing length are obviously not equivalent
    l = len(sets[0])
    for s in sets :
        if len(s) != l :
            return False

    sets_copy = copy.deepcopy(sets)
    for i in range(len(sets_copy)) :
        sets_copy[i].sort()

    for i in range(len(sets_copy[0])) :
        for j in range(len(sets_copy)) :
            if sets_copy[0][i] != sets_copy[j][i] :
                return False

    return True
    

def set_union (sets) :
    if len(sets) < 0 :
        return []

    result = []
    for s in sets :
        for ss in s :
            if ss not in result :
                result.append(ss)
    return result


def find_loop_dominator (dominators, loop) :
    dominator_sets = []
    # Get dominator sets for all nodes in loop
    for d in dominators :
        if d in loop :
            dominator_sets.append(copy.deepcopy(dominators[d]))
    # Remove all indicies not in loop
    for s in dominator_sets :
        i = 0
        while i < len(s) :
            if s[i] not in loop :
                del s[i]
            else :
                i += 1
    # The one dominator all vertices have in common is the head of this loop
    loop_dominator = set_intersection(dominator_sets)[0]
    return loop_dominator


def edge_list_get_tail_index (edge_list, tail_index) :
    '''
    Takes a list of edges and returns an edge if the tail_index matches the
    given index, or None otherwise.
    '''
    for edge in edge_list :
        if edge.tail_index == tail_index :
            return edge
    return None


class Edge:
    '''
    This class represents a generic edge in a graph. It does not contain
    references to its head and tail directly, but instead indicies to the head
    and tail.

    You should not store references to this edge directly.
    '''
    def __init__(self, graph, index, head_index, tail_index, data=None):
        '''
        Create an edge. You should not call this directly. Call
        graph.add_edge() instead.
        '''
        self.graph = graph
        self.index = index
        self.head_index = head_index
        self.tail_index = tail_index
        self.data = data

    def head (self) :
        '''
        Returns a reference to the head vertex of this edge.
        '''
        return self.graph.vertex_from_index(self.head_index)

    def tail(self):
        '''
        Returns a reference to the tail vertex of this edge.
        '''
        return self.graph.vertex_from_index(self.tail_index)


class Vertex:
    '''
    This class represents a generic vertex in a graph.
    '''
    def __init__(self, graph, index, data=None):
        '''
        Creates a vertex. You should not call this directly. Call
        graph.add_vertex() instead.
        '''
        self.graph = graph
        self.index = index
        self.data = data

    def get_predecessor_indices(self):
        predecessor_edges = self.graph.get_edges_by_tail_index(self.index)
        return map(lambda e: e.head_index, predecessor_edges)

    def get_predecessors(self):
        return map(lambda i: self.graph.get_vertex_from_index(i),
                   self.get_predecessor_indices())

    def get_successor_indices(self):
        successor_edges = self.graph.get_edges_by_head_index(self.index)
        return map(lambda e: e.tail_index, successor_edges)

    def get_successors(self):
        return map(lambda i: self.graph.get_vertex_from_index(i),
                   self.get_successor_indices())


class Graph:

    def __init__(self, entry_index=None):
        # When we create vertices, if an index is not specified, we increment
        # this to ensure we are creating unique vertex indicies
        self.next_vertex_index = -1000
        # A mapping of vertices by vertex index to vertex
        self.vertices = {}
        # When we create edges, we increment this to create unique edge indicies
        self.next_edge_index = 1

        # We keep references to the same edge in three different places to speed
        # up the searching for edges

        # A mapping of edges by edge index to edge
        self.edges = {}
        # A mapping of edges by head_index to edge
        self.edges_by_head_index = {}
        # A mapping of edges by tail_index to edge
        self.edges_by_tail_index = {}

        # An entry_index simplifies lots of stuff, like computing dominators
        self.entry_index = entry_index
        self.threshold = None

    def set_threshold(self, threshold):
        """
        Defining a Threshold to limit really big Functions for faster performance.
        :param threshold: Number (usually 100000 is good)
        :return:
        """
        self.threshold = threshold

    def add_edge(self, head, tail, data=None):
        '''
        Adds an edge to the graph by giving references to the head and tail
        vertices.
        This is just a wrapper for add_edge_by_indices.
        '''
        return self.add_edge_by_indices(head.index, tail.index, data)


    def add_edge_by_indices(self, head_index, tail_index, data=None):
        '''
        Adds an edge to the graph. Will fail if:
        1) There is no vertex in the graph for head_index.
        2) There is no vertex in the graph for tail_index.
        3) An edge already exists from head -> tail.

        @param head_index The index of the head vertex.
        @param tail_index The index of the tail vertex.
        @param data Any data you would like associated with this edge.
        @return A reference to the new edge if it was created, or None on
                failure.
        '''

        # Ensure we have a valid head and tail
        if not head_index in self.vertices:
            return None
        if not tail_index in self.vertices:
            return None

        # If we already have an edge here, don't add a new one
        if head_index in self.edges_by_head_index \
           and edge_list_get_tail_index(self.edges_by_head_index[head_index], tail_index) :
            return None

        # Create our new edge
        index = self.next_edge_index
        edge = Edge(self, index, head_index, tail_index, data)

        # Add it to our dict of edges
        self.edges[index] = edge

        # Add this edge to our lists of edges by head_index and tail_index
        if not head_index in self.edges_by_head_index:
            self.edges_by_head_index[head_index] = [edge]
        else :
            self.edges_by_head_index[head_index].append(edge)

        if not tail_index in self.edges_by_tail_index:
            self.edges_by_tail_index[tail_index] = [edge]
        else :
            self.edges_by_tail_index[tail_index].append(edge)

        # Return the edge
        return edge


    def add_vertex(self, index=None, data=None):
        '''
        Adds a vertex to the graph. Index represents a desired index for this
        vertex, such as an address in a CFG, and data represents data you would
        like to associate with this vertex. If no index is given, one will be
        assigned.

        @param index A desired index for this vertex
        @param data Data you would like to associate with this vertex
        @return The newly created vertex, or None if the vertex could not be
                created.
        '''
        if index == None:
            index = self.next_vertex_index
            self.next_vertex_index += 1
            while self.vertices.has_key(index):
                index = self.next_vertex_index
                self.next_vertex_index += 1
        else:
            if index in self.vertices:
                return None
        self.vertices[index] = Vertex(self, index, data)
        return self.vertices[index]


    def compute_dominators (self) :
        '''
        Returns a mapping of vertex indices to a list of dominators for that
        vertex.
        '''
        # We must have an entry_index to process dominators
        if self.entry_index == None:
            return None

        # Make a copy of this graph
        dag = self.directed_acyclic_graph()

        predecessors = dag.compute_predecessors()
        dominators = {}
        dominators[dag.entry_index] = [dag.entry_index]

        # queue of nodes to process
        queue = list(dag.get_vertex_from_index(dag.entry_index).get_successor_indices())

        while len(queue) > 0:
            vertex_index = queue[0]
            queue = queue[1:]
            vertex = dag.get_vertex_from_index(vertex_index)

            # are all predecessors for this vertex_index set?
            predecessors_set = True
            for predecessor_index in predecessors[vertex_index]:
                if predecessor_index not in dominators:
                    if predecessor_index not in queue:
                        queue.append(predecessor_index)
                    predecessors_set = False

            # if all predecessors are not set, they now come before this block
            # in the queue and will be set
            if not predecessors_set:
                queue.append(vertex_index)
                continue

            # all predecessors are set
            # This vertex's dominators are the intersection of all of its
            # immediate predecessors dominators
            doms = []
            for predecessor_index in vertex.get_predecessor_indices() :
                doms.append(copy.deepcopy(dominators[predecessor_index]))

            dominators[vertex_index] = set_intersection(doms)
            dominators[vertex_index].append(vertex_index)

            # add successors to the queue
            for successor_index in vertex.get_successor_indices() :
                if successor_index not in queue :
                    queue.append(successor_index)

        return dominators


    def compute_immediate_dominators (self) :
        '''
        Returns a mapping of vertex nodes to their immediate dominators.
        '''
        immediate_dominators = {}

        dominators = self.compute_dominators()

        # For every vertex
        for vertex_index in dominators :
            # Get all of this vertex's strict dominators
            sdoms = dominators[vertex_index]
            # Well, strict dominators
            i = 0
            while i < len(sdoms) :
                if sdoms[i] == vertex_index :
                    del sdoms[i]
                    break
                i += 1
            # Determine which strict dominator does not dominate any of the
            # other dominators
            for sdom in sdoms :
                is_immediate_dominator = True
                for d in dominators[vertex_index] :
                    # Don't check this strict dominator against itself
                    if sdom == d :
                        continue
                    # And don't check this strict dominator against this vertex
                    elif vertex_index == d :
                        continue
                    # Does this strict dominator exist in this dominator's dominators?
                    if sdom in dominators[d] :
                        is_immediate_dominator = False
                        break
                if is_immediate_dominator :
                    immediate_dominators[vertex_index] = sdom
                    break

        return immediate_dominators


    def compute_predecessors (self) :
        '''
        Returns a mapping of a vertex index to a list of vertex indices, where
        the key is given vertex and the value is a list of all vertices which
        are predecessors to that vertex.
        '''

        # Set our initial predecessors for each vertex
        predecessors = {}
        for vertex_index in self.vertices:
            vertex = self.vertices[vertex_index]
            predecessors[vertex_index] = list(vertex.get_predecessor_indices())

        # We now do successive propogation passes until we no longer propogate
        queue = list(self.vertices.keys())
        while len(queue) > 0:
            vertex_index = queue[0]
            queue = queue[1:]

            # for each predecessor of this vertex
            for predecessor_index in predecessors[vertex_index]:
                # Ensure all of these predecessor's are predecessors of this
                # vertex
                changed = False
                for pp_index in predecessors[predecessor_index]:
                    if pp_index not in predecessors[vertex_index]:
                        predecessors[vertex_index].append(pp_index)
                        changed = True
                # if we changed, add all successors to the queue
                if changed:
                    vertex = self.get_vertex_from_index(vertex_index)
                    successor_indices = vertex.get_successor_indices()
                    for s_index in successor_indices:
                        if s_index not in queue:
                            queue.append(s_index)

        return predecessors


    def directed_acyclic_graph (self) :
        # DAGs must have an entry node
        if self.entry_index == None :
            return None

        # copy this graph
        graph = Graph(self.entry_index)
        for vertex_index in self.vertices :
            graph.vertices[vertex_index] = Vertex(graph, vertex_index)

        predecessors = self.compute_predecessors()

        # a set of already visited verticex indices
        visited = []

        # A queue of indices to visit
        queue = [self.entry_index]

        valid_edges = []

        while len(queue) > 0 :
            vertex_index = queue[0]
            queue = queue[1:]

            # add this vertex_index to the visited set
            visited.append(vertex_index)

            # get the edges for all successors
            if vertex_index not in self.edges_by_head_index :
                continue

            edges = self.edges_by_head_index[vertex_index]
            for i in range(len(edges)) :
                edge = edges[i]
                # if this edge would create a loop, skip it
                if edge.tail_index in predecessors[edge.head_index] and \
                   edge.tail_index in visited :
                    continue

                # if we haven't seen this successor yet
                if edge.tail_index not in queue + visited :
                    # add it to the queue
                    queue.append(edge.tail_index)

                # this is a valid edge, add it
                graph.add_edge_by_indices(edge.head_index, edge.tail_index)

        return graph



    def detect_loops (self) :
        '''
        Detects loops in the graph, and returns a set of sets, where each
        internal set is the vertex indices of a detected loop.

        Requires self.entry_index to be set.
        '''

        def loop_dfs (path, vertex_index) :
            '''
            Takes a set of vertex indicies we have already walked, and the next
            vertex index to walk, and returns a set of sets, where each set is a
            detected loop
            @param path A set of indices we need to keep track of, but will not
                        search. This should be in order of the search.
            @param vertex_index The next vertex_index to walk
            '''
            loops = []

            # Grab the successor indices
            vertex = self.get_vertex_from_index(vertex_index)
            successor_indices = vertex.get_successor_indices()
            # For each successor
            for successor_index in successor_indices :
                # If this success is already in path, we have a loop
                if successor_index in path :
                    # We should truncate the path prior to successor_index
                    loop = copy.deepcopy(path)
                    loop.append(vertex_index)
                    loop = loop[loop.index(successor_index):]
                    loops.append(loop)
                # Keep searching
                else :
                    loops += loop_dfs(path + [vertex_index], successor_index)
            return loops

        loops = loop_dfs([], self.entry_index)
        

        # If we arrived at the same loop through different methods, we'll have
        # duplicates of the same loop, which we don't want. We need to remove
        # identical loop sets.
        for i in range(len(loops)) :
            loops[i].sort()

        # This creates a pseudo-hash table of the loops and guarantees
        # uniqueness
        loop_hashes = {}
        for i in range(len(loops)) :
            loop_hashes[",".join(map(lambda x: str(x), loops[i]))] = loops[i]

        loops = loop_hashes.values()

        # We now have unique traces through loops, but multiple traces through
        # the same loop will show up as different loops. We want to merge traces
        # for the same loop. We do this by finding the head of the loop for each
        # trace, and then performing a union over the sets of vertices for loops
        # with identical heads.
        dominators = self.compute_dominators()

        loop_heads = {}
        for loop in loops :
            loop_dominator = find_loop_dominator(dominators, loop)
            if loop_dominator not in loop_heads :
                loop_heads[loop_dominator] = loop
            else :
                loop_head = loop_heads[loop_dominator]
                loop_heads[loop_dominator] = set_union([loop_head, loop])

        return loop_heads.values()


    def get_edges_by_head_index (self, head_index) :
        '''
        Returns all edges who have a given head index. This is the same as the
        successor edges for a vertex by index.

        @param head_index The index of the vertex.
        @return A list of all edges with a head_index of head_index. An empty
                list will be returned if no such edges exist, including the case
                where a vertex with index head_index does not exist.
        '''
        if not head_index in self.edges_by_head_index:
            return []
        return self.edges_by_head_index[head_index]


    def get_edges_by_tail_index(self, tail_index):
        '''
        Returns all edges who have a given tail index. This is the same as the
        predecessor edges for a vertex by index.

        @param tail_index The index of the vertex.
        @return A list of all edges with a tail_index of tail_index. An empty
                list will be returned if no such edges exist, including the case
                where a vertex with index tail_index does not exist.
        '''
        if not tail_index in self.edges_by_tail_index:
            return []
        return self.edges_by_tail_index[tail_index]


    def get_vertex_from_index (self, index) :
        '''
        Returns a vertex with the given index.

        @param index The index of the vertex to retrieve.
        @return The vertex, or None if the vertex does not exist.
        '''
        if not index in self.vertices:
            return None
        return self.vertices[index]

    def get_vertices_data(self):
        return map(lambda x: x.data, [self.vertices[y] for y in self.vertices])

    def _find_all_paths(self, node, nodes, node_count, result, cur=list()):
        if self.threshold:
            if len(result) > self.threshold:
                return
        if node not in nodes:
            nodes.append(node)
            cur = [node]

        if len(nodes) == node_count or len(list(self.get_vertex_from_index(node).get_successor_indices())) == 0:
            if nodes not in result:
                result.append(nodes)
            return

        if node not in cur:
            cur.append(node)

        for i in self.get_vertex_from_index(node).get_successor_indices():
            if i not in cur:
                self._find_all_paths(i, nodes[:], node_count, result, cur[:])

    def compute_all_paths(self):
        sys.setrecursionlimit(10000)
        paths = list()
        self._find_all_paths(list(self.vertices)[0], list(), len(self.vertices), paths)

        path_basic_blocks = []
        for path in paths:
            tmp_blocks = []
            for index in path:
                tmp_blocks.append(self.get_vertex_from_index(index).data.basic_block)
            path_basic_blocks.append(tmp_blocks)
        return path_basic_blocks