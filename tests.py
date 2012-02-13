import sys, enc, os, struct, subprocess, assemble
from distorm3 import Registers, DecomposeGenerator, Decode32Bits

ut = []
count = 0

# unit test for register manipulation
def ut_reg(hex, eax=0x11111111, ecx=0x22222222, edx=0x33333333, ebx=0x44444444, esp=0x55555555, ebp=0x66666666, esi=0x77777777, edi=0x88888888):
	ut.append({'type': 'reg', 'hex': hex, 'regs': (eax % 2**32, ecx % 2**32, edx % 2**32, ebx % 2**32, esp % 2**32, ebp % 2**32, esi % 2**32, edi % 2**32)})

def test():
	global count
	for test in ut:
		test['asm'] = [] ; enc.Enc(None).reset_labels()
		test['lines'] = [
			'jmp m128_init0_end', 'align 16, db 0', 'm128_init0: dd 0x11111111, 0x22222222, 0x33333333, 0x44444444', 'm128_init0_end:',
			'jmp m128_init1_end', 'align 16, db 0', 'm128_init1: dd 0x55555555, 0x66666666, 0x77777777, 0x88888888', 'm128_init1_end:',
			'movapd xmm6, dqword [m128_init0]', 'movapd xmm7, dqword [m128_init1]']
		for dis in DecomposeGenerator(0, test['hex'].decode('hex'), Decode32Bits):
			test['lines'] += enc.Enc(dis).encode()
			test['asm'].append(str(dis))
		test['code'] = assemble.assemble(test['lines'], 'testing/' + str(count))
		
		sys.stderr.write('Processing %s -> %-32s\r' % (test['hex'], ' ; '.join(test['asm'])))
		output = struct.unpack('LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL', assemble.Debuggable(test['code']).run())
		if test['regs'] != output[24:]:
			print '%s -> %s gave problems (%d)!' % (test['hex'], ' ; '.join(test['asm']), count)
			print 'Generated SSE Assembly:\n' + '\n'.join(test['lines']) + '\n'
			# print all xmm registers
			for i in xrange(8): print 'xmm%d 0x%08x 0x%08x 0x%08x 0x%08x' % tuple([i] + list(output[i*4:i*4+4]))
			# print all gpr's stored in xmm registers, 16 is offset of EAX in the Registers array
			for i in xrange(8): print '%s 0x%08x -> 0x%08x' % (Registers[16+i], output[24+i], test['regs'][i])
			print '' # newline
			
			assemble.Debuggable(test['code']).debug()
		
		count += 1

def main():
	index = None
	tests = ['mov', 'xor', 'add']
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
	
	print str(tests), index
	
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
	
	# only do a certain test
	if index is not None: global ut ; ut = [ut[index]]
	
	test()

if __name__ == '__main__':
	main()