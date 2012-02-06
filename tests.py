import sys, enc, os, struct, distorm3, subprocess

ut = []
count = 0

def ut_test_write(lines):
	global count ; count += 1
	f = file('testing/%d.cpp' % count, 'w')
	f.write('#include <stdio.h>\n#include <windows.h>\nDWORD WINAPI XmmThread(LPVOID hEvent){')
	f.write('static unsigned long a[4] = {0x11111111, 0x22222222, 0x33333333, 0x44444444}, b[4] = {0x55555555, 0x66666666, 0x77777777, 0x88888888};')
	f.write('__asm__(".intel_syntax noprefix \\n"\n"mov eax, %0 \\n"\n"movapd xmm6, [eax] \\n"\n"mov eax, %1 \\n"\n"movapd xmm7, [eax] \\n"')
	f.write('"' + '\\n"\n"'.join(lines) + '\\n"\n')
	f.write('".att_syntax"	:: "r" (a), "r" (b)	: "eax"); SetEvent(hEvent); while (1); return 0; }')
	f.write('int main(){HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL); HANDLE hThread = CreateThread(NULL, 0, XmmThread, hEvent, 0, NULL);')
	f.write('WaitForSingleObject(hEvent, INFINITE); CONTEXT Ctx = {}; Ctx.ContextFlags = CONTEXT_FULL | CONTEXT_EXTENDED_REGISTERS;')
	f.write('GetThreadContext(hThread, &Ctx); fwrite(Ctx.ExtendedRegisters + 0xa0 + 16 * 6, 32, 1, stdout);}\n')
	f.close()
	# os.system('g++ testing.cpp -o testing')
	# return struct.unpack('LLLLLLLL', subprocess.Popen(['testing'], stdout=subprocess.PIPE).stdout.read())

# unit test for register manipulation
def ut_reg(hex, eax=0x11111111, ecx=0x22222222, edx=0x33333333, ebx=0x44444444, esp=0x55555555, ebp=0x66666666, esi=0x77777777, edi=0x88888888):
	ut.append({'type': 'reg', 'hex': hex, 'regs': (eax, ecx, edx, ebx, esp, ebp, esi, edi)})

def test(tests, compile):
	for test in ut:
		lines = [] ; test['asm'] = [] ; enc.Enc(None).reset_labels()
		for dis in distorm3.DecomposeGenerator(0, test['hex'].decode('hex'), distorm3.Decode32Bits):
			lines += enc.Enc(dis).encode()
			test['asm'].append(str(dis))
		ut_test_write(lines)
	
	# only write the file..
	if compile: return
	
	# 8 simultaneous jobs
	os.system('make -j 8 ' + ' '.join(tests) + ' test')
	
	count = 0
	for test in ut:
		count += 1
		sys.stderr.write('Processing %s -> %-32s\r' % (test['hex'], ' ; '.join(test['asm'])))
		output = struct.unpack('LLLLLLLL', subprocess.Popen(['./testing/%d.exe' % count], stdout=subprocess.PIPE).stdout.read())
		if test['regs'] != output:
			print '%s -> %s gave problems!' % (test['hex'], ' ; '.join(test['asm']))
			for i in xrange(8):
				print '0x%08x -> 0x%08x' % (output[i], test['regs'][i])

def main():
	compile = False
	if len(sys.argv) == 1:
		tests = ['mov', 'xor']
	elif sys.argv[1] == 'compile':
		tests = sys.argv[2:]
		compile = True
	else:
		tests = sys.argv[1:]
	
	if not os.access('testing', os.R_OK):
		os.mkdir('testing')
	
	if 'xor' in tests:
		# xor eax, eax
		ut_reg('33c0', eax=0)
		
		# xor edi, edi
		ut_reg('33ff', edi=0)
		
		# xor edx, 0x13371337
		ut_reg('81f237133713', edx=0x20042004)
		
		# xor al, al
		ut_reg('32c0', eax=0x11111100)
		
		# xor ax, ax
		ut_reg('6633c0', eax=0x11110000)
		
		# xor ecx, 0xdeadf00d
		ut_reg('81f10df0adde', ecx=0xfc8fd22f)
		
		# xor ecx, 3
		ut_reg('83f103', ecx=0x22222221)
		
		# xor ecx, 0x1337
		ut_reg('6681f13713', ecx=0x22223115)
		
		# xor eax, ebx
		ut_reg('33c3', eax=0x55555555)
	
	test(tests, compile)

if __name__ == '__main__':
	main()