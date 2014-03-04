# Copyright (c) <2013-2014>, <Samuel J. Tan (samueltan@gmail.com)>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# ====================================
# unset_scanner.py
# Unset register/memory scanner
# IDAPython script
# By Samuel Tan <samueltan@gmail.com>
# ====================================
#
# Prints instructions when a register or memory address is
# used without being set. Searches up to n instructions backwards
# along all possible execution paths from each candidate instruction,
# where n is provided by the user. 
#
# Supports scanning of MSP430X architecture instructions
#
# Pseudocode:
#   for each instruction
#       if instruction sets a register or memory address
#           for each n instructions before this instruction
#               if the register or memory is set, set flag
#           if flag is not set
#               print instruction and register/memory
#

from idaapi import *

# Returns true if the instruction is a jump instruction
# Returns false otherwise.
def is_jump_instr(ea):
    instr_name = GetMnem(ea)
    if 	(   ( instr_name == "call" )	or
            ( instr_name == "jc" )		or                
            ( instr_name == "jhs" )		or                
            ( instr_name == "jeq" )		or                
            ( instr_name == "jz" )		or                
            ( instr_name == "jge" )		or                
            ( instr_name == "jl" )		or                
            ( instr_name == "jmp" )		or                
            ( instr_name == "jn" )		or                
            ( instr_name == "jnc" )		or                
            ( instr_name == "jlo" )		or                
            ( instr_name == "jnz" )		or                
            ( instr_name == "jne" )		or                
            ( instr_name == "calla" ) ):
		return True
    return False

# Returns true if the instruction writes to or modifies
# a register or memory. Returns false otherwise.
def is_write_instr(ea):
    instr_name = GetMnem(ea)
    if not  (   ( instr_name == "bit" )		or
                ( instr_name == "br" )		or
                ( instr_name == "clr" )	    or                
                ( instr_name == "clrc" )	or                
                ( instr_name == "clrn" )	or                
                ( instr_name == "clrz" )	or                
                ( instr_name == "cmp" )		or                
                ( instr_name == "dint" )	or                
                ( instr_name == "eint" )	or   
                ( instr_name == "call" )    or  
                ( instr_name == "calla" )   or               
                ( instr_name == "jc" )		or                
                ( instr_name == "jhs" )		or                
                ( instr_name == "jeq" )		or                
                ( instr_name == "jz" )		or                
                ( instr_name == "jge" )		or                
                ( instr_name == "jl" )		or                
                ( instr_name == "jmp" )		or                
                ( instr_name == "jn" )		or                
                ( instr_name == "jnc" )		or                
                ( instr_name == "jlo" )		or                
                ( instr_name == "jnz" )		or                
                ( instr_name == "jne" )		or                
                ( instr_name == "nop" )		or                
                ( instr_name == "ret" )		or                
                ( instr_name == "reti" )	or                
                ( instr_name == "setc" )	or                
                ( instr_name == "setn" )	or                
                ( instr_name == "setz" )	or                
                ( instr_name == "tst" )		or                
                ( instr_name == "bitx" )	or                
                ( instr_name == "clrx" )	or                
                ( instr_name == "cmpx" )	or                
                ( instr_name == "tstx" )	or                
                ( instr_name == "bra" )		or                
                ( instr_name == "clra" )	or 
                ( instr_name == "reta" )	or 
                # TODO: push is technically a write instruction,
                # but considering it usually brings up a lot of false
                # positives since pushes usually occur in function
                # postambles, and the corresponding pop instruction
                # (that sets memory) occurs much earlier in the function
                # preamble
                ( instr_name == "push" )   or 
                ( instr_name == "pushx" )   or 
                ( instr_name == "pushm" )   or
                ( instr_name == "pop" )     or 
                ( instr_name == "popx" )    or 
                ( instr_name == "tsta" ) ):
        return True
    return False

# Returns true if the instruction sets
# the register or memory (reg_mem). Returns false otherwise.
def is_set_instr( ea, reg_mem ):
    instr_name = GetMnem(ea)
    if  (((instr_name == "mov") or (instr_name == "movx"))
            and (GetOpnd(ea, 1) == reg_mem)):
        return True
    elif (((instr_name == "clr") or (instr_name == "clrx"))
            and (GetOpnd(ea, 0) == reg_mem)):
        return True
    elif (((instr_name == "and") or (instr_name == "andx"))
            and (GetOperandValue(ea, 0) == 0)):
        return True
    elif (((instr_name == "pop") or (instr_name == "popx"))
            and (GetOpnd(ea, 0) == reg_mem)):
        return True
    return False

def reg_is_used(ea):
	return (is_write_instr(ea) or is_jump_instr(ea))

# If set instruction is not found, returns (False, BADADDR)
# Otherwise, returns (True, ea) where ea is the address where the
# set instruction is found at
def find_set_instr(head, seg_ea, instr_searched, src):
    curr_ea = PrevHead(head, seg_ea)
    head_of_block = False
    while ( (instr_searched > 0) and
            (not head_of_block)  and
            (curr_ea != BADADDR) ):
        
        if (isCode(GetFlags(curr_ea))):
        	# Found a set instruction
            if (is_set_instr(curr_ea, src)):
                return True, curr_ea

            # Search all possible paths to enter this instruction
            if (isRef(GetFlags(curr_ea))):
                for ref_ea in CodeRefsTo(curr_ea, 0):
                    found_set_instr, found_ea = find_set_instr(ref_ea, 
                        seg_ea, instr_searched - 1, src)
                    if (found_set_instr):
                        return True, found_ea
                if (not isFlow(GetFlags(curr_ea))):
                    head_of_block = True

        curr_ea = PrevHead(curr_ea, seg_ea)
        instr_searched -= 1

    return False, BADADDR

# For an instruction at a user-given address, search backwards n 
# instructions for a set instruction
def search_instr_at_addr():
    head = AskAddr(ScreenEA(), "Enter address of addr to search from: ")
    search_dist = AskLong(30, "Please enter how many instructions to search "
        "backwards for each candidate write instruction")
    mnem = GetMnem(head)
    src = GetOpnd(head, 0)
    print "src is %s" %(src)
    found_set_instr, found_ea = find_set_instr(head, SegStart(head), 
        search_dist, src)
    if (found_set_instr):
        print "Set instruction for %s found!" %(src)
        print "%08x\t %s" %(found_ea, GetDisasm(found_ea))
    else:
        print "No set instruction found!"

# Searches disassembly for instances where a
# register is used but not set before
def search():
    search_dist = AskLong(30, "Please enter how many instructions to search \
        backwards for each candidate write instruction")

    num_found = 0

    # For each of the segments
    for seg_ea in Segments():
        
        # For each of the defined elements
        for head in Heads(seg_ea, SegEnd(seg_ea)):
            
            if isCode(GetFlags(head)):
                # If it is a write instruction, we search
                # for a corresponding instruction that sets
                # the src before it
                if ( reg_is_used(head) and GetOpnd(head, 0)[:1] == "R"):
                    src = GetOpnd(head, 0)
                    
                    if (not find_set_instr(head, seg_ea, search_dist, src)[0]):
                    	print "%08x\t %s" %(head, GetDisasm(head))
                    	num_found += 1

    print "Searched %d instructions backwards per candidate instruction" %(search_dist)
    print "Total candidate unset write instructions found: %d" %(num_found)

# Executed commands          
search()
# search_instr_at_addr()