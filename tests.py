import sys, enc, os, struct, subprocess, assemble
from distorm3 import Registers, DecomposeGenerator, Decode32Bits
from ctypes import *

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40

ut = []
count = 0

# unit test for register manipulation
def ut_reg(hex, eax=0x11111111, ecx=0x22222222, edx=0x33333333, ebx=0x44444444, esp=0xb00b0ffc, ebp=0x66666666, esi=0x77777777, edi=0x88888888):
	ut.append({'type': 'reg', 'hex': hex, 'regs': (eax % 2**32, ecx % 2**32, edx % 2**32, ebx % 2**32, esp % 2**32, ebp % 2**32, esi % 2**32, edi % 2**32)})

# unit test for register manipulation *and* memory stuff
def ut_mem(hex, eax=0x11111111, ecx=0x22222222, edx=0x33333333, ebx=0x44444444, esp=0xb00b0ffc, ebp=0x66666666, esi=0x77777777, edi=0x88888888, mem=[0,0,0,0]):
	if len(mem) != 4: mem = mem + [0 for i in xrange(4 - len(mem))]
	ut.append({'type': 'mem', 'hex': hex, 'regs': (eax % 2**32, ecx % 2**32, edx % 2**32, ebx % 2**32, esp % 2**32, ebp % 2**32, esi % 2**32, edi % 2**32), 'mem': mem[::-1]})

def test(debug):
	global count
	_stack = cdll.msvcrt.malloc(4 * 4)
	stack = _stack + 4 * 4
	code = windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	for test in ut:
		test['asm'] = [] ; enc.Enc(None).reset_labels()
		test['lines'] = [
			'jmp m128_init0_end', 'align 16, db 0', 'm128_init0: dd 0x11111111, 0x22222222, 0x33333333, 0x44444444', 'm128_init0_end:',
			'jmp m128_init1_end', 'align 16, db 0', 'm128_init1: dd 0x%08x, 0x66666666, 0x77777777, 0x88888888' % stack, 'm128_init1_end:',
			'movapd xmm6, dqword [m128_init0]', 'movapd xmm7, dqword [m128_init1]']
		for dis in DecomposeGenerator(0, test['hex'].decode('hex'), Decode32Bits):
			test['lines'] += enc.Enc(dis).encode()
			test['asm'].append(str(dis))
		test['code'] = assemble.assemble(test['lines'], 'testing/' + str(count))
		
		sys.stderr.write('Processing %s -> %s (%d)\r' % (test['hex'], ' ; '.join(test['asm']), count))
		output = list(struct.unpack('L' * 36, assemble.Debuggable(test['code'], _stack, code).run()))
		# adjust the `esp' register to remain correctly.. :)
		if (output[28] >> 16) == (stack >> 16): output[28] = 0xb00b0ffc - stack + output[28]
		if test['type'] in ['reg', 'mem'] and test['regs'] != tuple(output[24:32]):
			print '%s -> %s gave register problems (%d)!' % (test['hex'], ' ; '.join(test['asm']), count)
			print 'Generated SSE Assembly:\n' + '\n'.join(test['lines']) + '\n'
			# print all xmm registers
			for i in xrange(8): print 'xmm%d 0x%08x 0x%08x 0x%08x 0x%08x' % tuple([i] + list(output[i*4:i*4+4]))
			# print all gpr's stored in xmm registers, 16 is offset of EAX in the Registers array
			for i in xrange(8): print '%s 0x%08x -> 0x%08x' % (Registers[16+i], output[24+i], test['regs'][i])
			print '' # newline
			
			assemble.Debuggable(test['code'], _stack, code).debug()
		
		# unit test with memory changes
		elif test['type'] == 'mem' and test['mem'] != output[32:]:
			print '%s -> %s gave memory problems (%d)!' % (test['hex'], ' ; '.join(test['asm']), count)
			print 'Generated SSE Assembly:\n' + '\n'.join(test['lines']) + '\n'
			
			# print the memory stuff
			for i in xrange(len(output)-32): print '%-3d: 0x%08x -> 0x%08x' % (i, output[32+i], test['mem'][i])
			print '' # newline
			
			assemble.Debuggable(test['code'], _stack, code).debug()
		
		elif debug:
			assemble.Debuggable(test['code'], _stack, code).debug()
		
		count += 1
	
	# free the stack
	cdll.msvcrt.free(_stack)
	
	# free the machine code
	windll.kernel32.VirtualFree(code, 0, MEM_RELEASE)

def main():
	index = None
	tests = ['mov', 'or', 'and', 'xor', 'add', 'inc', 'dec', 'xchg', 'push', 'pop', 'not', 'neg', 'leave']
	if len(sys.argv) > 1:
		argc = 1
		try:
			index = int(sys.argv[argc])
			argc += 1
		except:
			index = None
		
		if argc != len(sys.argv):
			tests = sys.argv[argc:]
	
	if not os.access('testing', os.R_OK):
		os.mkdir('testing')
	
	eax = 0x11111111
	ax  = 0x1111
	al  = 0x11
	ah  = 0x11
	ecx = 0x22222222
	cx  = 0x2222
	cl  = 0x22
	ch  = 0x22
	edx = 0x33333333
	dx  = 0x3333
	dl  = 0x33
	dh  = 0x33
	ebx = 0x44444444
	bx  = 0x4444
	bl  = 0x44
	bh  = 0x44
	# stack memory.. at address 0xb00b0000 with size = 0x1000
	esp = 0xb00b0ffc
	sp  = 0xfffc
	ebp = 0x66666666
	bp  = 0x6666
	esi = 0x77777777
	si  = 0x7777
	edi = 0x88888888
	di  = 0x8888
	
	if 'xor' in tests:
		# xor eax, eax
		ut_reg('33c0', eax=0)
		
		# xor edi, edi
		ut_reg('33ff', edi=0)
		
		# xor edx, 0x13371337
		ut_reg('81f237133713', edx=edx^0x13371337)
		
		# xor ebx, 0xdeadcafe
		ut_reg('81f3fecaadde', ebx=ebx^0xdeadcafe)
		
		# xor al, al
		ut_reg('32c0', eax=0x11111100)
		
		# xor ax, ax
		ut_reg('6633c0', eax=0x11110000)
		
		# xor ecx, 0xdeadf00d
		ut_reg('81f10df0adde', ecx=ecx^0xdeadf00d)
		
		# xor ecx, 3
		ut_reg('83f103', ecx=ecx^3)
		
		# xor ecx, 0x1337
		ut_reg('6681f13713', ecx=ecx^0x1337)
		
		# xor eax, ebx
		ut_reg('33c3', eax=eax^ebx)
		
		# xor edx, eax
		ut_reg('33d0', edx=edx^eax)
		
		# xor ecx, esi
		ut_reg('33ce', ecx=ecx^esi)
	
	if 'or' in tests:
		# or esi, 0xffff0000
		ut_reg('81ce0000ffff', esi=esi|0xffff0000)
		
	if 'and' in tests:
		# and ebx, 0x00ffff00
		ut_reg('81e300ffff00', ebx=ebx&0x00ffff00)
	
	if 'mov' in tests:
		# mov ebx, edx
		ut_reg('8bda', ebx=edx)
		
		# mov esi, ebx
		ut_reg('8bf3', esi=ebx)
		
		# mov ecx, 0xdeadf00d
		ut_reg('b90df0adde', ecx=0xdeadf00d)
		
		# mov cx, 0xd00d
		ut_reg('66b90dd0', ecx=0x2222d00d)
		
		# mov cl, 0x42
		ut_reg('b142', ecx=0x22222242)
		
		# mov cx, si
		ut_reg('668bce', ecx=0x7777)
		
		# mov esp, ebp
		ut_reg('8be5', esp=ebp)
	
	if 'add' in tests:
		# add ecx, esi
		ut_reg('03ce', ecx=ecx+esi)
		
		# add ebx, 0xcafebabe
		ut_reg('81c3bebafeca', ebx=ebx+0xcafebabe)
	
	if 'inc' in tests:
		# inc eax
		ut_reg('40', eax=eax+1)
		
		# inc esi
		ut_reg('46', esi=esi+1)
	
	if 'dec' in tests:
		# dec eax
		ut_reg('48', eax=eax-1)
		
		# dec esi
		ut_reg('4e', esi=esi-1)
	
	if 'xchg' in tests:
		# xchg ebx, ecx
		ut_reg('87cb', ebx=ecx, ecx=ebx)
		
		# xchg edx, edi
		ut_reg('87fa', edx=edi, edi=edx)
	
	if 'push' in tests or 'pop' in tests:
		# push 0x13371337
		ut_mem('6837133713', esp=esp-4, mem=[0x13371337])
		
		# push 0xdeadf00d ; pop edx
		ut_mem('680df0adde5a', mem=[0xdeadf00d], edx=0xdeadf00d)
		
		# push 0xabcddcba ; push 0xdefdefde
		ut_mem('68badccdab68deeffdde', mem=[0xabcddcba, 0xdefdefde], esp=esp-8)
	
	if 'not' in tests:
		# not eax
		ut_reg('f7d0', eax=~eax)
		
		# not eax ; not eax
		ut_reg('f7d0' * 2)
	
	if 'neg' in tests:
		# neg eax
		ut_reg('f7d8', eax=-eax)
		
		# xor eax, eax ; dec eax ; neg eax
		ut_reg('33c048f7d8', eax=1)
	
	if 'leave' in tests:
		# push 0x12345678 ; mov ebp, esp ; leave
		ut_mem('68785634128becc9', mem=[0x12345678], ebp=0x12345678)
	
	# this crashes python, so this can only be executed
	# by explicitely defining `ret' on the commandline
	if 'ret' in tests:
		# push 0x41414141 ; retn
		ut_mem('6841414141c3')
	
	# only do a certain test
	debug = False
	if index is not None:
		global ut
		ut = [ut[index]]
		debug = True
	
	test(debug)

if __name__ == '__main__':
	main()