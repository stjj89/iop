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
# reentrant_int_scanner.py
# Reentrant interrupt scanner
# IDAPython script
# By Samuel Tan <samueltan@gmail.com>
# ====================================
#
# Lists instructions within an interrupt handler
# potentially re-enables the interrupt itself 
# (i.e. by writing to the register containng the
# interrupt enable bit and/or the status register),
# thereby making it reentrant.
#
# User provides the address of the first instruction
# in the instruction handler, and how many instructions
# to search ahead from that instruction.
# 
#
from idaapi import *

# Switch to control debug print statements
DEBUG = True

# Returns true iff the ie_reg_addr or the SR is used as an 
# instruction operand
def potential_ie_set_instr(ea, ie_reg_addr):
    op_type_1 = GetOpType(ea, 0)
    op_type_2 = GetOpType(ea, 1)
    op_val_1 = GetOperandValue(ea, 0)
    op_val_2 = GetOperandValue(ea, 1)
    op_text_1 = GetOpnd(ea, 0)
    op_text_2 = GetOpnd(ea, 1)
    # ie_reg_addr used as a memory reference operand
    if (op_type_1 == 2) and (op_val_1 == ie_reg_addr):
        return True
    if (op_type_2 == 2) and (op_val_2 == ie_reg_addr):
        return True
    # SR is an operand
    if (op_type_1 == 1) and (op_text_1 == 'SR'):
        return True
    if (op_type_2 == 1) and (op_text_2 == 'SR'):
        return True
    return False

# Search all possible execution paths from the
# given head for a potential interrupt enable instruction,
# printing them if they are encountered
# Terminates at a maximum depth to prevent infinitely
# searching through spin loops
def find_ie_instr(head, seg_ea, ie_reg_addr, max_depth):
    # Terminate search at max depth
    if (max_depth == 0):
        return

    curr_ea = NextHead(head, seg_ea)
    instr_name = GetMnem(curr_ea)

    if (not isCode(GetFlags(curr_ea))) or (instr_name == "reti"):
        if (instr_name == "reti"):
            if DEBUG:
                print "#DEBUG RETI reached at %04x" %(curr_ea)
        return

    if (potential_ie_set_instr(curr_ea, ie_reg_addr)):
            print "0x%04x\t%s" %(curr_ea, GetDisasm(curr_ea))
        
    # Call recursively on all possible branches
    for ref in CodeRefsFrom(curr_ea, 1):
        find_ie_instr(ref, seg_ea, ie_reg_addr, max_depth-1)

def find_all_ie_instr():
    ea = AskAddr(ScreenEA(), 'Please enter interrupt handler start address')
    ie_reg_addr = AskAddr(0x0, 'Please enter address of peripheral register'
     'containing interrupt enable bit')
    max_depth = AskLong(100, 'Please enter a max search depth')
    print 'Instructions re-enabling interrupts within handler'
    print '==================================================='
    find_ie_instr(ea, SegEnd(ea), ie_reg_addr, max_depth)
    print ''


# Executed command
find_all_ie_instr()