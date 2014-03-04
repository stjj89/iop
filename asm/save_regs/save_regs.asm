; ==========================================
; save_regs.asm
; MSP430 firmware
; By Samuel Tan <samueltan@gmail.com>
; ==========================================
;
; Simple MSP430 Firmware with a reset
; handler that dumps all registers to
; known addresses in RAM
;
; Used to determine values loaded in MSP430
; registers after a hard reset (i.e. read
; values written to memory addresses on a
; separate JTAG debugging session)

    .org 0x3100
start:
    mov.w R0, &0x200
    mov.w R1, &0x202
    mov.w R2, &0x204
    mov.w R3, &0x206
    mov.w R4, &0x208
    mov.w R5, &0x20a
    mov.w R6, &0x20c
    mov.w R7, &0x20e
    mov.w R8, &0x210
    mov.w R9, &0x212
    mov.w R10, &0x214
    mov.w R11, &0x216
    mov.w R12, &0x218
    mov.w R13, &0x21a
    mov.w R14, &0x21c
    mov.w R15, &0x21e
repeat:
    jmp repeat
  
    .org 0xfffe
    .word 0x3100

