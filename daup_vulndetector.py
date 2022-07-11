import os
import json
import copy

class Stack:
    """Stack implementation as a list"""
    def __init__(self):
        """Create new stack"""
        self._items = []
    def is_empty(self):
        """Check if the stack is empty"""
        return not bool(self._items)
    def push(self, item):
        """Add an item to the stack"""
        self._items.append(item)
    def pop(self):
        """Remove an item from the stack"""
        return self._items.pop()
    def peek(self):
        """"Get the value of the top item"""
        return self._items[-1]
    def size(self):
        """Get the number of items in the stack"""
        return len(self._items)
    def __str__(self):
        return str(self._items)

#Implementation of the abstract data types (1st Checkpoint)

class Pattern:
    """Represents a vulnerability pattern, including all its components (vulnerability name, sources, sanitizers and sinks), 
    and it is used to define Policies.

    param pattern: Dictionary with vulnerability name, sources, sanitizers and sinks.
    complexity: O(1)
    """
   

    def __init__(self, pattern) -> None:
        self.__P = pattern
    
        self.__vulnerability = self.__P['vulnerability']
        self.__source = self.__P['sources']
        self.__sanitizers = self.__P['sanitizers']
        self.__sinks = self.__P['sinks']
        

    def get_vulnerability(self) -> str:
        """Returns pattern's vulnerability name as string.
        
        complexity: O(1)
        """
        return self.__vulnerability
    
    def get_sanitizers(self) -> list:
        '''Returns pattern's list of sanitizers as strings.
        
        complexity: O(1)
        '''
        return self.__sanitizers
    
    def get_sources(self) -> list:  
        '''Returns pattern's list of sources as strings.
        
        complexity: O(1)
        ''' 
        return self.__source
    
    def get_sinks(self) -> list:
        '''Returns pattern's list of sinks as strings.
        
        complexity: O(1)
        ''' 
        return self.__sinks

    def is_source(self, possible_source) -> bool:
        '''Returns True or False indicating whether the given name is a source of self.
        
        param possible_source: string corresponding to source name to test.
        complexity: O(N)
        '''
        return possible_source in self.get_sources() 
        

    def is_sanitizer(self, possible_sanitizer) -> bool:
        '''Returns True or False indicating whether the given name is a sanitizer of self.
        
        param possible_sanitizer: string corresponding to sanitizer name to test.
        complexity: O(N)
        '''
        return possible_sanitizer in self.get_sanitizers() 
       

    def is_sink(self, possible_sink) -> bool:
        '''Returns True or False indicating whether the given name is a sink of self.
        
        param possible_sink: string corresponding to sink name to test.
        complexity: O(N)
        '''
        return possible_sink in self.get_sinks() 

    def __str__(self) -> str:
        """Allows to print the pattern object as a string.

        complexity: O(N)
        """ 
        return str(self.__P)
    
    def __repr__(self) -> str:
        """Returns the pattern object as a string, making it the oficial representation of this object.

        complexity: O(N)
        """ 
        return str(self.__P)
    
    def __eq__(self, other) -> bool:
        """Allows the user to know whether self and other given pattern object have the same vulnerability, using the symbol "==".

        complexity: O(1)
        """ 
        return self.get_vulnerability() == other.get_vulnerability()




class Flow:
    """Represents an information flow from a source. 
    It is used to build Labels that represent which flows might have influenced a certain piece of data.
    
    complexity: O(1)
    """
    def __init__(self,source_0) -> None:
        self.__source=source_0

    def get_source(self) -> str:
        """Returns the name of the source where the flow represented by self starts.
        
        complexity: O(1)
        """
        return self.__source

    def same_source(self, other_flow) -> bool:
        """True or False indicating whether self and other given flow have the same source.
        
        param other_flow: Flow object to be compared with self
        complexity: O(1)
        """
        return self.get_source()==other_flow.get_source()
        
    def copy_flow(self):
        """Returns a copy of self.
        
        complexity: O(1)
        """
        return Flow(self.__source)

    def __str__(self) -> str:
        """Allows to print the source of the flow as a string.
        
        complexity: O(1) 
        """
        return str(self.__source)

    def __eq__(self, other_flow) -> bool:
        """Allows the user to know whether self and other given flow have the same source, using the symbol "==".
        
        param other_flow: Flow object to be compared.
        complexity: O(1)
        """
        return self.same_source(other_flow)

    def __hash__(self) -> int:
        """Enables to make the Flow class hashable.
        
        complexity: O(1)
        """
        return hash(self.__source) 
    
    def __repr__(self) -> str:
        """Enables to make the Flow class representable.
        
        complexity: O(1)
        """
        return str(self.__source)




class Policy:
    """Represents the current information flow policy that determines which flows are illegal.
    
    complexity: O(1)
    """

    def __init__(self) -> None:
        self.__Pol = {}
        self.__updated = True
        self.__vulnerabilities = []


    def get_vulnerabilities(self) -> list:
        """Returns the list of vulnerability names that are valid in self.
        
        complexity: O(P), except when it is used during analysis of the program, O(1) in that case.
        ADTs where it corresponds to O(1): Label and IllegalFlows.
        """

        if self.__updated == False:
            self.__vulnerabilities = self.__Pol.keys() 
            self.__updated = True

        return self.__vulnerabilities


    def add_pattern(self, pattern) -> None:
        """Given a Policy object self and another Pattern object, changes self to include that additional pattern.
        
        param pattern: Pattern object to be added.
        return: Policy object with given pattern included, if self does not have any pattern with the same name.
        complexity: O(1) 
        """

        if pattern.get_vulnerability() in self.__vulnerabilities:
            print(f"Vulnerability name of given pattern ({pattern.get_vulnerability()}) already included in Policy.")
            return 
    
        self.__Pol[pattern.get_vulnerability()] = pattern
        self.__vulnerabilities.append(pattern.get_vulnerability())


    def delete_pattern(self, name) -> None:
        """Given a Policy object self and a vulnerability name, changes self to exclude that pattern.

        param name: string corresponding to the vulnerability name of pattern to be deleted.
        return: Policy object with pattern corresponding to the given name excluded, if self has a pattern with the same name.
        complexity: O(1)
        """

        if name not in self.__vulnerabilities:
            print(f"Given pattern name ({name}) not found. No pattern was deleted from the Policy.")
            return
        
        del self.__Pol[name]
        self.__updated = False


    def get_vulnerabilities_source(self, source) -> list: 
        """Given a source name, returns the list of vulnerability names for which the given name is a source.
        
        param source: string corresponding to a source name.
        return: List of vulnerability names for for which the given name is a source.
        complexity: O(P*N)
        """
        vulnerabilities=[]
        for p in self.__Pol.values():
            if p.is_source(source):
                vulnerabilities.append(p.get_vulnerability())
        
        return vulnerabilities
    

    def get_vulnerabilities_sanitizer(self, sanitizer) -> list:
        """Given a sanitizer name, returns the list of vulnerability names for which the given name is a sanitizer.
        
        param sanitizer: string corresponding to a sanitizer name.
        return: List of vulnerability names for which the given name is a sanitizer.
        complexity: O(P*N)
        """
        vulnerabilities=[]
        for p in self.__Pol.values(): 
            if p.is_sanitizer(sanitizer):
                vulnerabilities.append(p.get_vulnerability())
        
        return vulnerabilities 


    def get_vulnerabilities_sink(self, sink) -> list:
        """Given a sink name, returns the list of vulnerability names for which the given name is a sink.
        
        param sink: string corresponding to a sink name.
        return: List of vulnerability names for which the given name is a sink.
        complexity: O(P*N)
        """
        vulnerabilities=[]
        for p in self.__Pol.values(): 
            if p.is_sink(sink):
                vulnerabilities.append(p.get_vulnerability())
        
        return vulnerabilities 


    def get_sanitizers_vulnerability(self, vulnerability) -> list: 
        """Given a vulnerability name, returns the list of sanitizer names corresponding to the given vulnerability
        
        param vulnerability: string corresponding to a vulnerability name.
        return: List of sanitizer names corresponding to the given vulnerability.
        complexity: O(1)
        """
        if vulnerability in self.__Pol: 
            pattern = self.__Pol[vulnerability]
            return pattern.get_sanitizers()
        
        print(f"Vulnerability {vulnerability} not found.") 
  

    def illegal_flows(self, label, name):
        """Given the Policy object self, a Label object and a name as a string, returns a 
        new Label object representing only the flows represented in the original Label object that
        should not reach a sink with the given name.
        
        param label: Label object to be changed in order to contain only illegal flows.
        param name: string corresponding to a sink name.
        return: New Policy object with flows that should not reach a sink with the given name.
        complexity: O(P.N) 
        """
        not_sink = [p.get_vulnerability() for p in self.__Pol.values() if not p.is_sink(name)]
        new_label = label.copy_label()
        for vul in not_sink:
            new_label.clear_flows(vul)
        return new_label


    def __str__(self) -> str:
        """Prints the Policy’s patterns by alphabetical order of vulnerability name.
        
        complexity: O(P**2) 
        """
        sorted_keys=sorted(self.__Pol.keys())
        list_patterns=[]
        for key in sorted_keys:
            list_patterns.append(self.__Pol[key])
        return str(list_patterns)




class Label:
    """Used to represent all the information flows that might have influenced a certain piece of data.
    
    param policy: Policy object that guides the analysis.
    complexity: O(P)
    """
    
    def __init__(self, policy) -> None:
        self.__policy = policy 
        self.__label_sources = {}
        self.__vulnerabilities = self.__policy.get_vulnerabilities()
        for i in self.__vulnerabilities:
            self.__label_sources[i] = set()


    def add_if_source(self, source) -> None:
        """Changes self so as to include a new flow starting at that source for all vulnerabilities for which that name is a source.
        
        param source: string corresponding to a source for which a new flow will start.
        complexity: O(P.N)
        """
        
        vuln_to_add = self.__policy.get_vulnerabilities_source(source)
        if vuln_to_add != None:
            for i in vuln_to_add:
                self.__label_sources[i].add(Flow(source)) 
        
        
    def clear_flows(self, vulnerability_name) -> None:
        """Changes self so as to erase any flows associated to the given vulnerability.
        
        param vulnerability_name: string corresponding to vulnerability name.
        complexity: O(1)
        """
        if vulnerability_name in self.__label_sources:  
            self.__label_sources[vulnerability_name] = set() 
        else:
            print(f"{vulnerability_name} not found in labels vulnerabilities ")

    def sanitize(self, sanitizer) -> None: 
        """Changes self so as to erase all Flows associated to all vulnerabilities that have that sanitizer.
        
        param sanitizer: string corresponding to a sanitizer.
        complexity: O(P.N)
        """
        vuln_to_del = self.__policy.get_vulnerabilities_sanitizer(sanitizer)
        if vuln_to_del != None:
            for i in vuln_to_del:
                self.__label_sources[i] = set()

    def get_flows_vulnerability(self, vulnerability_name) -> set: 
        """Returns the set of flows corresponding to the given vulnerability.
        
        param vulnerability_name: string corresponding to a vulnerability name.
        complexity: O(1)
        """
        if vulnerability_name in self.__label_sources: 
            return self.__label_sources[vulnerability_name] 
        else:
            print(f"{vulnerability_name} not found in labels vulnerabilities ")

    def copy_label(self):
        """Returns a Label object that is a deep copy of self.
        
        return: New Label object corresponding to a deep copy of self.
        complexity: O(P*N)
        """
        
        new_label = Label(self.__policy)
        for i in self.__vulnerabilities: 
            flow_set = copy.deepcopy(self.get_flows_vulnerability(i)) 
            new_label.add_flows_vuln(i, flow_set)
        return new_label 
    
    def add_flows_vuln(self, vulnerability_name, flow_set) -> None: 
        """Adds a given set with flows to a given vulnerability in the current label, erasing the set with flows that was there.
        (Auxiliary method for label_combine method.)
        
        param vulnerability_name: string corresponding to a vulnerability name.
        param flow_set: set with flows.
        complexity: O(1)
        """ 
        self.__label_sources[vulnerability_name] = flow_set

    def label_combine(self, other_label):
        """Returns a new Label object that results from combining the two that were received.
        
        param other_label: Label object to be combined.
        return: New Label object with all Flows for all vulnerabilities in both of them.
        complexity: O(N*P)
        """
        new_label = Label(self.__policy) 
        for i in self.__vulnerabilities:
            sources_our_label = self.__label_sources[i]
            sources_other_label = other_label.get_flows_vulnerability(i) 
            new_flow_set = sources_our_label.union(sources_other_label)
            new_label.add_flows_vuln(i, new_flow_set)
        return new_label 
    
    
    def __add__(self,other_label):
        """Allows the user to combine two labels (using the method label_combine) using the "+" symbol.
        
        complexity: O(N*P) 
        """
        return self.label_combine(other_label)

    def __eq__(self,other_label) -> bool:
        """Allows the user to know whether self and other given label have the same sources in each vulnerability, using the symbol "=".

        param other_label: Label object to be compared.
        complexity: O(P.N)
        """
        return self.__label_sources == other_label.__label_sources 
    
    def __str__(self) -> str:
        """Allows to print a string with the vulnerabilities of the Label, each with the correspondig flows (printed as sources).
        
        complexity: O(P*N)
        """

        return str(self.__label_sources)

    def __repr__(self) -> str:
        """Returns the label object as a string, making it the oficial representation of this object.

        complexity: O(P*N)
        """

        return str(self.__label_sources)


#Implementation of the Abstract Data Types (2nd Checkpoint)

class Context(Stack):
    """Represents the information that is carried by the control flow of the program being analysed.

    complexity: O(1)
    """

    def __init__(self) -> None:
        """Initializes a new Context object, corresponding to a Stack object."""
        super().__init__()

    def enter_block_label(self, label) -> None:
        """Updates the Context so as to represent the updated context label.

        param label: Label object that represents the implicit flows
        complexity: O(P.N)
        """
        if self.in_block():
            previous_label = self.peek()
            labels_combined = previous_label.label_combine(label)
            self.push(labels_combined)
        else:
            self.push(label)

    def exit_block(self) -> None:
        """Updates the Context so as to discard the implicit flows that were added when entering the innermost block.

        complexity: O(1)
        """
        if self.in_block():
            self.pop() 
        else:
            print('No block is currently represented in the Context.') 
    
    def in_block(self) -> bool:
        """Returns the value True or False indicating whether self holds a label corresponding to some block.

        complexity: O(1) 
        """
        return not self.is_empty() 
    
    def get_block_label(self):
        """Returns the Label object that represents all the implicit flows that affect the current block.

        complexity: O(1)
        """
        if self.in_block():
            return self.peek()
    
        print('No block is currently represented in the Context.')

    
    def __str__(self) -> str:
        """Allows to print the Context as a string.

        complexity: O(S*P*N)
        """
        return str(self._items)

    def __repr__(self) -> str:
        """Allows the Context to be represented.

        complexity: O(S*P*N)
        """
        return str(self._items)

class IllegalFlows:
    """Used to collect all the illegal flows that are discovered during the analysis of the program slice.

    complexity: O(P), assuming that when we initialize this ADT the policy gets updated 
    """
    def __init__(self, policy) -> None:
        #IllegalFlows format = {vulnerability: illegal_flows}; illegal_flows: 'source -> sink' (string)

        self.__policy = policy
        self.__vulnerabilities = policy.get_vulnerabilities()
        self.__illegal_flows = {} 
        
    
    
    def get_illegal_flows(self, label, sink) -> None:
        """Updates self so as to include any illegal flows that result when information with the given label reaches a sink with the given name.

        param label: Label object.
        param sink: string corresponding to a sink name.
        complexity: O(P.N)
        """
        label_illegal_flows = self.__policy.illegal_flows(label, sink) 
        
        for vul in self.__vulnerabilities:
            if label_illegal_flows.get_flows_vulnerability(vul) != None: 
                illegal_flows = label_illegal_flows.get_flows_vulnerability(vul) 
                
                str_illegal_flows = [f"{source} -> {sink}" for source in illegal_flows]
                
                if vul in self.__illegal_flows:
                    if len(str_illegal_flows) != 0:
                        
                        self.__illegal_flows[vul].append(str_illegal_flows[0]) 
                else:
                    self.__illegal_flows[vul] = str_illegal_flows
                    
 
    def __str__(self) -> str:
        """Prints the illegal flows for each vulnerability name, sorted by lexicographic order of vulnerability name and of source name. 
        
        complexity: O(P*LOG(P)*N**2*LOG(N))
        """
        string = ''
        
        for vuln in self.__vulnerabilities:
            if vuln not in self.__illegal_flows:
                string += f'Vulnerability {vuln} not detected. \n'
                
        for vul in sorted(self.__illegal_flows.keys()):  
            self.__illegal_flows[vul]=set(self.__illegal_flows[vul]) 
            self.__illegal_flows[vul]=list(self.__illegal_flows[vul])
            self.__illegal_flows[vul].sort()
            if self.__illegal_flows[vul] == []:
                string += f'Vulnerability {vul} not detected. \n' 
        
            else:
                if self.__policy.get_sanitizers_vulnerability(vul) != []:
                    recommended_sanitizers = self.__policy.get_sanitizers_vulnerability(vul)
                else:
                    recommended_sanitizers = 'None known :('
                  
                string += f'Vulnerability {vul} detected! \nIllegal flows: {self.__illegal_flows[vul]} \nRecommend sanitizers: {recommended_sanitizers} \n' #O(N**2) 

        return string


class LabelMap:
    """Represents a mapping from variable names to labels, according to which information flows might have affect the values in the variables.

    complexity: O(1)"""

    def __init__(self):
        self.__label_map = {}

    def is_labelled(self,variable): 
        """ Returns True or False whether the variable given as a string is given a label.
        
        complexity: O(1)""" 
        return variable in self.__label_map
    
    def map_name_to_label(self,variable,label): 
        """ Updates self so as to map the given variable to the given label
        
        complexity O(1)"""
        self.__label_map[variable] = label

    def labmap_combine(self,other_label_map):
        """ Combines to labelmaps including all variables in both mapped to all Flows for all vulnerabilities in both.
        Recieves: Two different labelmaps.
        Returns: A new labelmap that is the combination of the two given.
         
        Complexity: O(S*N*P) """
        new_label_map = LabelMap()
        for i in self.__label_map.keys(): 
            first_label = self.__label_map[i] 
            if i in other_label_map.__label_map: 
                second_label = other_label_map.__label_map[i] 
                combined_label = first_label.label_combine(second_label) 
                new_label_map.map_name_to_label(i,combined_label)
            else: 
                new_label_map.map_name_to_label(i,first_label)
        for i in other_label_map.__label_map.keys(): 
            if i not in self.__label_map:
                second_label = other_label_map.__label_map[i]
                new_label_map.map_name_to_label(i,second_label)
            
        return new_label_map

    def get_copy_label(self,variable): 
        """ Creates a deep copy of the label that is mapped by self from the given variable.
        
        complexity: O(P*N)""" 
        if variable not in self.__label_map:
            print('This variable is not yet in this maplabel object.')
            return 
        real_label = self.__label_map[variable]
        copy_label = real_label.copy_label()
        return copy_label

    def __str__(self):
        """Allows to print a string with the variables of the maplabel, each with the correspondig labels.
        
        complexity: O(P*N*S)""" 
        return str(self.__label_map) 

    def __repr__(self):
        """Returns the labmap object as a string, making it the oficial representation of this object.
        
        complexity: O(P*N*S)""" 
        return str(self.__label_map) 

    def __eq__(self, other_label):
        """Allows the user to know whether self and other given labelmap are the same, using the symbol "=".

        param other_label: LabelMap object to be compared.
        complexity: O(P*N*S)
        """
        return self.__label_map == other_label.__label_map
    
    def __add__(self, other_label):
        """Allows the user to combine two labelmaps (using the method labmap_combine) using the "+" symbol.
        
        complexity: O(S*N*P)
        """
        return self.labmap_combine(other_label)


#Implementation of the Abstract Data Types (3rd Checkpoint)

class Analyser:
    """Represents the analysis functionality of the tool.
    It includes methods for traversing different program constructs and returning the information collected during the traversal. 

    complexity: O(1)
    """
    def __init__(self, policy, illegalflows):
        self.__policy = policy
        self.__illegalflows = illegalflows
        self.__context = Context()

    def expr_name(self, ast, labelmap):
        """Returns a new Label object representing the information flows that are carried by the name for which the label is mapped. 

        param ast: AST expression node of the type Name
        param labelmap: LabelMap object
        complexity: O(P*N)
        """

        variable = ast['id']
        if labelmap.is_labelled(variable): #O(1)
            label_to_return = labelmap.get_copy_label(variable) #O(P*N)
        else:
            label_to_return = Label(self.__policy) #O(P)

        return label_to_return

    def expr_binop(self, ast, labelmap):
        """Returns a new Label object containing a combination of the flows carried by each of the sub-expressions of the binary operation. 

        param ast: AST expression node of the type BinOp
        param labelmap: LabelMap object
        complexity: O(S**2*N*P), the worst case scenario is when the recursive calls are always to the function expr_call.
        """
        
        left = ast['left']
        right = ast['right']
        label_left = self.expr_label(left, labelmap)
        label_right = self.expr_label(right, labelmap)
        label_to_return = label_left + label_right #O(N*P) 
        return label_to_return 

    def expr_compare(self, ast, labelmap):
        """Returns a new Label object containing a combination of the flows carried by each of the sub-expressions of the comparison. 

        param ast: AST expression node of the type Compare
        param labelmap: LabelMap object
        complexity: O(S**2*N*P), the worst case scenario is when the recursive calls are always to the function expr_call.
        """
        
        comparators = ast['comparators'][0]
        left = ast['left']
        label_left = self.expr_label(left, labelmap)
        label_right = self.expr_label(comparators, labelmap)
        label_to_return = label_left + label_right  #O(N*P) 
        return label_to_return

    def expr_call(self, ast, labelmap):
        """Returns a new Label object representing the information flows that are carried by the function call.

        param ast: AST expression node of the type Call
        param labelmap: LabelMap object
        complexity: O(S**2*N*P)
        """

        func_name = ast['func']['id']
        args = ast['args']
        
        combined_labels = Label(self.__policy)
        for arg in args: #O(S)
            arg_label = self.expr_label(arg, labelmap) 
            combined_labels += arg_label  #O(N*P) 
    
        if self.__context.in_block(): #O(1)
            label_in_context = self.__context.get_block_label() #O(1)
            combined_labels += label_in_context  #O(N*P) 
        
        combined_labels.add_if_source(func_name) #O(P.N)

        combined_labels.sanitize(func_name) #O(P.N)
        
        self.__illegalflows.get_illegal_flows(combined_labels, func_name) #O(P.N) 
        
        return combined_labels

    
    def expr_label(self, ast, labelmap):
        """Returns a new Label object representing the information flows that are carried by the expression.

        param ast: AST expression node
        param labelmap: LabelMap object
        complexity: O(S**2*N*P) 
        """

        ast_type = ast['ast_type'] #O(1)
    
        if ast_type == 'Constant':
            label_to_return = Label(self.__policy) #O(P)
        
        elif ast_type == 'Name':
            label_to_return = self.expr_name(ast, labelmap) #O(P*N)

        elif ast_type == 'BinOp':
            label_to_return = self.expr_binop(ast, labelmap) #complexity in the worst case scenario equal to the expr_call one: O(S**2*N*P)

        elif ast_type == 'Compare':
            label_to_return = self.expr_compare(ast, labelmap) #complexity in the worst case scenario equal to the expr_call one: O(S**2*N*P)

        elif ast_type == 'Call':
            label_to_return = self.expr_call(ast, labelmap) #O(S**2*N*P)

        else:
            print('The given ast type is not Constant, Name, BinOp, Compare nor Call.') #O(1)
            label_to_return = None #O(1)
        return label_to_return

    def traverse_assign(self, ast, labelmap):
        """Returns a new LabelMap object that is like the one received as argument, but that also takes note of the flows introduced by the assignment.

        param ast: AST statement node of the type Assign
        param labelmap: LabelMap object
        complexity: O(S**2*N*P) 
        """
        
        expr_node = ast['value']
        variable_name = ast['targets'][0]['id']

        label = self.expr_label(expr_node, labelmap) #O(S**2*N*P)
        if self.__context.in_block():
            label_in_context = self.__context.get_block_label() #O(1)
            label = label + label_in_context #O(N*P)
        
        labelmap.map_name_to_label(variable_name, label) #O(1)
       
        return labelmap


    def traverse_if (self, ast, labelmap):
        """Returns a new LabelMap object that is like the one received as argument, but that also takes note of the flows introduced by the if condition. 

        param ast: AST statement node of the type If
        param labelmap: LabelMap object
        complexity: O(S**3*N*P), the worst case scenario is when the recursive calls are always to the function traverse_while.
        """ 
        
        test_branch = ast['test']
        if_branch = ast['body']
        else_branch = ast['orelse']
        
        label_to_context = self.expr_label(test_branch,labelmap) #O(S**2*N*P)
        self.__context.enter_block_label(label_to_context) #O(P.N)
        
        copy_labelmap = copy.deepcopy(labelmap) #O(P.N.S)

        #traverse the if and else branch independently
        if_branch_labmap = self.traverse(if_branch, labelmap) 
        
        else_branch_labmap = self.traverse(else_branch, copy_labelmap) 
        
        #combine the labels found for each variable
        labmap_to_return = if_branch_labmap + else_branch_labmap #O(S*N*P)
        
        self.__context.exit_block() #O(1)
        
        return labmap_to_return
    
    
    def traverse_while(self, ast, labelmap):
        """Returns a new LabelMap object that is like the one received as argument, but that also takes note of the flows introduced by the while loop.

        param ast: AST statement node of the type While
        param labelmap: LabelMap object
        complexity: O(S**3*N*P)
        """ 
        
        test_branch = ast['test']
        body_branch = ast['body']
        
        label_to_context = self.expr_label(test_branch, labelmap) #O(S**2*N*P)
        self.__context.enter_block_label(label_to_context) #O(P.N)
    
        
        copy_labelmap = copy.deepcopy(labelmap) #O(P.N.S)
        copy_labelmap = self.traverse(body_branch, copy_labelmap)
        while labelmap != copy_labelmap: #O(S)
            labelmap = copy_labelmap #O(1)
            copy_labelmap = copy.deepcopy(labelmap) #O(P.N.S)
            copy_labelmap += self.traverse(body_branch, copy_labelmap)
           
        labmap_to_return = copy_labelmap

        self.__context.exit_block() #O(1)
        
        return labmap_to_return


    def traverse(self, ast, labelmap):
        """Returns a new LabelMap object that is like the one received as argument, but that also takes note of the flows introduced by the statement. 

        param ast: AST statement node
        param labelmap: LabelMap object
        complexity: O(S**3*N*P)
        """
        
        
        if type(ast) == list:
            if len(ast)==0:
                labmap_to_return = labelmap
            else:
                for element in ast: #O(S)
                    if element == ast[0]:
                        current_labelmap = labelmap
                    else:
                        current_labelmap += labmap_to_return # O(S*N*P)
                       
                    labmap_to_return = self.traverse(element, current_labelmap) 
                
                    
        else:
            ast_type = ast['ast_type']

            if ast_type == 'Assign':
                labmap_to_return = self.traverse_assign(ast, labelmap) #O(S**2*N*P)
        
            elif ast_type == 'If':
                labmap_to_return = self.traverse_if(ast, labelmap) #complexity in the worst case scenario equal to the traverse_while one: O(S**3*N*P)

            elif ast_type == 'While':
                labmap_to_return = self.traverse_while(ast, labelmap) #O(S**3*N*P)

            elif ast_type == 'Expr':
                self.expr_label(ast['value'], labelmap) #O(S**2*N*P)
                labmap_to_return = labelmap 
        
        return labmap_to_return
        


#Definition of functions to use in Interaction Cycle

def read_ast_file(file_name):
    """To export Python program to json ast and import json ast to Python representation.
    
    complexity: O(S)
    """
    #export Python program to json ast
    os.system("astexport <"+file_name+"> myveryowntemp")
    
    #import json ast to Python representation
    with open("myveryowntemp") as fp1:
        ast_json=fp1.read()
    ast=json.loads(ast_json)
    os.system("rm myveryowntemp")
    return ast
    

def read_patterns_file(cmd):
    """To import jsons patterns to Python representation.
    
    complexity: O(P*N)
    """
    with open(cmd) as fp2:
        pat_str=fp2.read()
        pat_json=pat_str.replace('\n','')
        patterns=json.loads(pat_json)
        
    return patterns


#Definition of functions to print the AST represented in JSON.


def print_json(part_ast):
    ''' Prints the AST of the currently stored program slice, using the JSON format, and indentations that help visualize its structure.
    
    param part_ast: part of the AST 
    Complexity: O(S) - this complexity already takes into account the functions used recursively - print_dict and print_list
    '''
    if type(part_ast)==dict:
        print_dict(part_ast)

    elif type(part_ast)==list:
        print_list(part_ast)

    elif type(part_ast)==str or type(part_ast)==int:
        print (part_ast,end="")

    else:
        print(f'Type of {part_ast} is not dict, list, int, nor str',end="")
        return ''


def print_dict(dicti):
    if len(dicti)==0:
        print('{}',end="")

    else:
        ident='  '
        print('{')
        cont_ident.push(1)
        clean_keys=[] #this list will have the keys we want in the final print
        for i in dicti.keys():
            if i in ["args", "func", "id", "left", "right", "comparators", "ast_type", "targets", "value", "test", "body", "orelse"]:
                clean_keys+=[i]

        for i in clean_keys:    
            print(ident*cont_ident.size() + i + ': ', end=""),
            print_json(dicti[i])

            if i != clean_keys[-1]: #prints a comma if it is not the last value of the dictionary
                print(',')

        cont_ident.pop()
        print('')
        print(ident*cont_ident.size()+'}',end="")

def print_list(list_0):
    if len(list_0)==0:
        print('[]',end="")

    else:
        ident='  '
        print('[')
        cont_ident.push(1)
        for i in list_0:
            print(ident*cont_ident.size(),end="")
            print_json(i)

            if i != list_0[-1]: #prints a comma if it is not the last value of the list
                print(',')

        cont_ident.pop()
        print('')
        print(ident*cont_ident.size()+']',end="") 


#Interaction Cycle

while True:
    
    temp = input('Enter command:')
    letter = temp[0]
    rest = temp[2:]
    
    if letter == 'x':
        break

    elif letter == 'c':
        
        try:
            display = open(file_name, "r").read()
            print(f"The program currently stored is: \n {display}")
        except NameError:
            print ("No program currently stored.")
        
        try:
            print(f"The policy currently stored is: \n {pol}")
        except NameError:
            print("No policy currently stored.")
        
    
    elif letter == 'p':
        file_name = rest
        ast = read_ast_file(file_name)

    elif letter == 'b':
        pol = Policy()
        pattern_prov = read_patterns_file(rest) 
        for i in pattern_prov:
            pat = Pattern(i)
            pol.add_pattern(pat)

    elif letter == 'e': 
        rest = json.loads(rest)
        pat = Pattern(rest)
        pol.add_pattern(pat)

    elif letter == 'd':
        pol.delete_pattern(rest)

    elif letter == 'j':
        cont_ident = Stack() #create a stack of values 1  and according to its len, the print will have the the right identation at any time.
        try:
            print_json(ast)
            print('')
        except NameError:
            print ("No AST currently stored.")
    
    elif letter == 'a':
        illegalflows = IllegalFlows(pol)
        
        a = Analyser(pol, illegalflows)

        labelmap = LabelMap()

        a.traverse(ast['body'], labelmap)

        print(illegalflows)
            
    elif letter == 'h':
        print("Valid Commands: \n p file_name: read a new Python program slice to analyse from file file_name.\
        \n b file_name: read new base vulnerability patterns from file file_name.\
        \n e json_pattern: extend base vulnerabilities with json_pattern.\
        \n d vuln_name: delete vulnerability pattern vuln_name from base.\
        \n c: show current program slice and vulnerability patterns.\
        \n j: pretty print the AST represented in JSON.\
        \n a: analyse the current program slice.\
        \n x: exit the program.")

    else:
        print('Command not valid. For help write: h.')