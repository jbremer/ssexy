import sys, enc, os, struct, subprocess
from distorm3 import Registers, DecomposeGenerator, Decode32Bits

ut = []
count = 0

def ut_test_write(lines):
	global count ; count += 1
	f = file('testing/%d.cpp' % count, 'w')
	f.write('#include <stdio.h>\n#include <windows.h>\nDWORD WINAPI XmmThread(LPVOID){')
	f.write('static unsigned long a[4] = {0x11111111, 0x22222222, 0x33333333, 0x44444444}, b[4] = {0x55555555, 0x66666666, 0x77777777, 0x88888888};')
	f.write('__asm__(".intel_syntax noprefix \\n"\n"mov eax, %0 \\n"\n"movapd xmm6, [eax] \\n"\n"mov eax, %1 \\n"\n"movapd xmm7, [eax] \\n"')
	f.write('"' + '\\n"\n"'.join(lines) + '\\n"\n')
	f.write('".att_syntax"	:: "r" (a), "r" (b)	: "eax"); while (1); return 0; }')
	f.write('int main(){HANDLE hThread = CreateThread(NULL, 0, XmmThread, NULL, 0, NULL); Sleep(10);')
	f.write('CONTEXT Ctx = {}; Ctx.ContextFlags = CONTEXT_FULL | CONTEXT_EXTENDED_REGISTERS;')
	f.write('GetThreadContext(hThread, &Ctx); fwrite(Ctx.ExtendedRegisters + 0xa0, 8, 16, stdout);}\n')
	f.close()

# unit test for register manipulation
def ut_reg(hex, eax=0x11111111, ecx=0x22222222, edx=0x33333333, ebx=0x44444444, esp=0x55555555, ebp=0x66666666, esi=0x77777777, edi=0x88888888):
	ut.append({'type': 'reg', 'hex': hex, 'regs': (eax % 2**32, ecx % 2**32, edx % 2**32, ebx % 2**32, esp % 2**32, ebp % 2**32, esi % 2**32, edi % 2**32)})

def test(tests, compile):
	for test in ut:
		test['lines'] = [] ; test['asm'] = [] ; enc.Enc(None).reset_labels()
		for dis in DecomposeGenerator(0, test['hex'].decode('hex'), Decode32Bits):
			test['lines'] += enc.Enc(dis).encode()
			test['asm'].append(str(dis))
		ut_test_write(test['lines'])
	
	# only write the file..
	if compile: return
	
	# 8 simultaneous jobs
	os.system('make -j 8 ' + ' '.join(tests) + ' test')
	
	count = 0
	for test in ut:
		count += 1
		sys.stderr.write('Processing %s -> %-32s\r' % (test['hex'], ' ; '.join(test['asm'])))
		output = struct.unpack('LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL', subprocess.Popen(['./testing/%d.exe' % count], stdout=subprocess.PIPE).stdout.read())
		if test['regs'] != output[24:]:
			print '%s -> %s gave problems!' % (test['hex'], ' ; '.join(test['asm']))
			print 'Generated SSE Assembly:\n' + '\n'.join(test['lines']) + '\n'
			# print all xmm registers
			for i in xrange(8): print 'xmm%d 0x%08x 0x%08x 0x%08x 0x%08x' % (i, output[i*4+0], output[i*4+1], output[i*4+2], output[i*4+3])
			# print all gpr's stored in xmm registers, 16 is offset of EAX in the Registers array
			for i in xrange(8): print '%s 0x%08x -> 0x%08x' % (Registers[16+i], output[24+i], test['regs'][i])
			print '' # newline

def main():
	compile = False
	if len(sys.argv) == 1:
		tests = ['mov', 'xor', 'add']
	elif sys.argv[1] == 'compile':
		tests = sys.argv[2:]
		compile = True
	else:
		tests = sys.argv[1:]
	
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
	esp = 0x55555555
	sp  = 0x5555
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
	
	if 'add' in tests:
		# add ecx, esi
		ut_reg('03ce', ecx=ecx+esi)
		
		# add ebx, 0xcafebabe
		ut_reg('81c3bebafeca', ebx=ebx+0xcafebabe)
	
	test(tests, compile)

if __name__ == '__main__':
	main()