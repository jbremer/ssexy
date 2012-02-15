import os, struct, distorm3
from ctypes import *

WAIT_TIMEOUT = 0x102

CONTEXT_X86                 = 0x00010000
CONTEXT_CONTROL             = CONTEXT_X86 | 0x1L # SS:SP, CS:IP, FLAGS, BP
CONTEXT_INTEGER             = CONTEXT_X86 | 0x2L # AX, BX, CX, DX, SI, DI
CONTEXT_SEGMENTS            = CONTEXT_X86 | 0x4L # DS, ES, FS, GS
CONTEXT_FLOATING_POINT      = CONTEXT_X86 | 0x8L # 387 state
CONTEXT_DEBUG_REGISTERS     = CONTEXT_X86 | 0x10L # DB 0-3,6,7
CONTEXT_EXTENDED_REGISTERS  = CONTEXT_X86 | 0x20L # cpu specific extensions
CONTEXT_FULL                = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS

ESP = 4

kernel32 = windll.kernel32
msvcrt = cdll.msvcrt

def assemble(lines, fname):
	lines.insert(0, 'bits 32')
	lines.insert(1, 'org 0xfed0000')
	file('%s.asm' % fname, 'w').write('\n'.join(lines))
	os.system('yasm -mx86 %s.asm -o%s' % (fname, fname))
	ret = open(fname, 'rb').read()
	os.unlink('%s.asm' % fname)
	os.unlink(fname)
	return ret

class _CONTEXT(Structure):
	_fields_ = [
		('ContextFlags', c_uint),
		('Unused0', c_char * 180),
		('Eip', c_uint),
		('Unused1', c_char * (16 + 0xa0)),
		('Xmm', c_uint * 32),
		('Unused2', c_char * (512-0xa0))
	]

class _Stack(Structure):
	_fields_ = [
		('Mem', c_uint * 4)
	]

class Debuggable:
	def __init__(self, machine_code, stack, code):
		# copy of the raw machine code we have to process
		self.machine_code = machine_code
		
		# memory for our real machine code
		self.code = code
		
		# stack of our stuff
		self.stack = stack
		
		# list of instructions and m128s, for debugging purposes
		self.instructions = []
		self.m128s = {}
	
	def _run(self, machine_code, verbose = False):
		# copy the buffer directly to memory
		msvcrt.memcpy(self.code, byref(create_string_buffer(machine_code)), len(machine_code))
		
		# clean the stack.. :) that is, zero it out.
		kernel32.WriteProcessMemory(-1, self.stack, byref(_Stack()), 4 * 4, None)
		
		# create new thread
		hThread = kernel32.CreateThread(None, None, self.code, None, None, None)
		
		# initialize the instructions variabele
		index = 0 ; self.instructions.append('RETN')
		lastEip = None
		lastXmm = [0 for i in xrange(32)]
		lastMem = [0 for i in xrange(4)]
		
		# give it one millisecond every time to execute the following instruction..
		while kernel32.WaitForSingleObject(hThread, 1) == WAIT_TIMEOUT:
			context = _CONTEXT()
			stack = _Stack()
			
			context.ContextFlags = CONTEXT_FULL | CONTEXT_EXTENDED_REGISTERS
			kernel32.SuspendThread(hThread)
			kernel32.GetThreadContext(hThread, byref(context))
			
			# eip is not in our code section, let's just continue
			if context.Eip < self.code or context.Eip > self.code + len(machine_code):
				kernel32.ResumeThread(hThread)
				continue
			
			# read the stack memory here (so it also works in non-verbose mode)
			kernel32.ReadProcessMemory(-1, self.stack, byref(stack), 4 * 4, None)
			
			# if eip didn't change yet or eip is not even in our code section yet, continue..
			if context.Eip == lastEip:
				kernel32.ResumeThread(hThread)
				continue
			
			# print the xmm registers and the stack memory
			if verbose:
				# print the xmm registers that will be altered by this instruction before the instruction
				for i in xrange(8):
					if context.Xmm[i*4:i*4+4] != lastXmm[i*4:i*4+4]:
						print 'xmm%d  0x%08x 0x%08x 0x%08x 0x%08x' % tuple([i] + lastXmm[i*4:i*4+4])
				
				# print the instruction (with possibly the m128 referenced)
				print '0x%08x: %s' % (0xfed0000 + context.Eip - self.code, self.instructions[index])
				
				# print the xmm registers after the instructions
				for i in xrange(8):
					if context.Xmm[i*4:i*4+4] != lastXmm[i*4:i*4+4]:
						print 'xmm%d  0x%08x 0x%08x 0x%08x 0x%08x' % tuple([i] + context.Xmm[i*4:i*4+4])
				lastXmm = context.Xmm
				
				# TODO: Come up with a better way to read the stack memory
				if lastMem != list(stack.Mem):
					print 'stack', ' '.join(map(lambda x: '0x%08x' % x, stack.Mem))
					lastMem = list(stack.Mem)
				
				print '' # newline
			
			# store the last eip
			lastEip = context.Eip
			
			# skip the while(1) loop
			context.Eip += 2
			index += 1
			
			# continue the debugging stuff
			kernel32.SetThreadContext(hThread, byref(context))
			kernel32.ResumeThread(hThread)

		# close our thread handle
		kernel32.CloseHandle(hThread)
		
		# return the Xmm registers and memory registers
		return ''.join(map(lambda x: struct.pack('L', x), list(context.Xmm) + list(stack.Mem)))
	
	def debug(self):
		# disasm the machine code, to obtain each instruction so we can place a while(1) between them
		buf = '' ; offset = 0 ; addr = {}
		while offset != len(self.machine_code):
			instr = distorm3.Decompose(None, self.machine_code[offset:])[0]
			hexdump = instr.instructionBytes.encode('hex')
			
			# increase offset
			offset += len(hexdump) / 2
			
			# short jmp, we have to skip this.. (16-byte aligned m128)
			if hexdump[:2] == 'eb':
				# calculate the jmp-length
				jmp_len = int(hexdump[2:], 16)
				
				# extract the m128
				m128 = self.machine_code[offset+jmp_len-16:offset+jmp_len]
				
				# align to 16 bytes and write the m128 (including jmp over it)
				# 32 bytes = 30 bytes align + 2 bytes short jmp
				buf += '90'*(30 - (len(buf)/2 % 16)) + 'eb10' + m128.encode('hex')
				
				# write this addr in our dictionary
				addr[0xfed0000+offset+jmp_len-16] = self.code + len(buf)/2 - 16
				
				# keep a dictionary with address -> m128
				self.m128s[0xfed0000+offset+jmp_len-16] = struct.unpack('LLLL', m128)
				
				offset += jmp_len
			# normal and sse instructions are followed by a while(1) loop
			else:
				buf += hexdump + 'ebfe'
				
				# if referenced, display m128 as well
				m128 = ''
				if instr.operands[1].type == distorm3.OPERAND_ABSOLUTE_ADDRESS:
					m128 = '\nm128  ' + ' '.join(map(lambda x: '0x%08x' % x, self.m128s[instr.operands[1].disp]))
				
				self.instructions.append(str(instr).lower() + m128)
		
		# replace all old addresses with new addresses, using a sortof bad way
		for key, value in addr.items():
			buf = buf.replace(struct.pack('L', key).encode('hex'), struct.pack('L', value).encode('hex'))
		
		# exit the thread after a last while(1) loop, to get the final xmm registers
		buf += 'ebfec3'
		
		return self._run(buf.decode('hex'), True)
	
	def run(self):
		# i hope for the sake of simplicity that 0xfed is quite unlikely, in normal assembly..
		code = self.machine_code.replace(struct.pack('H', 0xfed), struct.pack('H', self.code >> 16))
		return self._run(code + '\xeb\xfe\xc3')
