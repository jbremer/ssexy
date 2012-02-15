import sys, binascii, assemble, distorm3
from distorm3 import OPERAND_REGISTER, OPERAND_IMMEDIATE, OPERAND_MEMORY, OPERAND_ABSOLUTE_ADDRESS

def enc_apply(hex):
	return Enc(distorm3.Decompose(0, hex.decode('hex'), distorm3.Decode32Bits)[0]).encode()

class Enc:
	_labels = {}
	_ff_flag = {8: 0xff, 16: 0xffff, 32: 0xffffffff}
	
	def __init__(self, dis):
		if not dis: return
		self.dis = dis
		self.reg_index1 = None
		self.reg_index2 = None
		self.xmm_index1 = None
		self.xmm_index2 = None
		self.xmm_reg1 = None
		self.xmm_reg2 = None
		self.lines = []
		
		if len(dis.operands) > 0:
			self.type1 = dis.operands[0].type
			if self.type1 == OPERAND_REGISTER:
				self.reg_index1 = dis.operands[0].index & 7
				self.xmm_index1 = dis.operands[0].index & 3
				self.xmm_reg1 = self._xmm_gpr_index(self.reg_index1)
				self.size1 = self.dis.operands[0].size
			elif self.type1 == OPERAND_IMMEDIATE:
				self.imm1 = self.dis.operands[0].value
			elif self.type1 == OPERAND_ABSOLUTE_ADDRESS:
				self.type1 = OPERAND_MEMORY
		
		if len(dis.operands) > 1:
			self.type2 = dis.operands[1].type
			if self.type2 == OPERAND_REGISTER:
				self.reg_index2 = dis.operands[1].index & 7
				self.xmm_index2 = dis.operands[1].index & 3
				self.xmm_reg2 = self._xmm_gpr_index(self.reg_index2)
				self.size2 = self.dis.operands[1].size
			elif self.type2 == OPERAND_IMMEDIATE:
				self.imm2 = self.dis.operands[1].value
			elif self.type2 == OPERAND_ABSOLUTE_ADDRESS:
				self.type2 = OPERAND_MEMORY
	
	# reset labels dict
	def reset_labels(self):
		Enc._labels = {}
	
	def encode(self):
		func = getattr(self, '_encode_' + self.dis.mnemonic.lower(), None)
		if not func: raise Exception('Cannot encode %s' % self.dis.mnemonic.lower())
		func()
		return self.lines
	
	# find register for gpr
	def _xmm_gpr_index(self, gpr_index):
		return 'xmm%d' % (6 + gpr_index / 4)
	
	# construct a 16byte xmm value
	def _m128(self, val):
		if str(val) not in Enc._labels:
			self.lines.append('jmp m128_%d_end' % len(Enc._labels))
			self.lines.append('align 16, db 0')
			self.lines.append('m128_%d: ' % len(Enc._labels) + 'dd 0x%08x, 0x%08x, 0x%08x, 0x%08x' % tuple(val))
			self.lines.append('m128_%d_end:' % len(Enc._labels))
			Enc._labels[str(val)] = 'dqword [m128_%d]' % len(Enc._labels)
		return Enc._labels[str(val)]
	
	# construct a 16byte xmm value from 4 dwords
	def _m128_flag4(self, index, yes=0, no=0):
		val = [no for i in range(4)]
		val[index] = yes
		return self._m128(val)
	
	# construct a 16byte xmm value from 8 words
	def _m128_flag8(self, index, yes=0, no=0):
		val = [no for i in range(8)]
		val[index * 2] = yes
		return self._m128([(val[i] + (val[i+1] << 16)) for i in xrange(0, 8, 2)])
	
	# construct a 16byte xmm value from 16 bytes
	def _m128_flag16(self, index, yes=0, no=0):
		val = [no for i in range(16)]
		val[index * 4] = yes
		return self._m128([reduce(lambda x, y: x * 256 + y, val[i:i+4][::-1]) for i in xrange(0, 16, 4)])
	
	def _m128_flagsize(self, index, yes=0, no=0, size=32):
		if size == 32:   return self._m128_flag4(index, yes, no)
		elif size == 16: return self._m128_flag8(index, yes, no)
		elif size == 8:  return self._m128_flag16(index, yes, no)
		raise Exception('dafuq')
	
	# calculate the flag for pshufd instruction
	def _flag_pshufd(self, index, value, flags=[0,0,0,0]):
		flags[index & 3] = value & 3
		return reduce(lambda x, y: x * 4 + y, flags)
	
	# read a 8bit, 16bit or 32bit integer from a memory address, optionally give it a special position
	def _read_mem(self, reg, addr, size=32, position=0):
		self.lines.append('movss xmm%d, [0x%x]' % (reg, addr))
		if size != 32:
			self.lines.append('pand xmm%d, %s' % (reg, self._m128([self._ff_flag[size], 0, 0, 0])))
		if position != 0:
			self.lines.append('pshufd xmm%d, xmm%d, %d' % (reg, reg, self._flag_pshufd(position, 0)))
	
	# write a 8bit, 16bit or 32bit value to an address
	def _write_mem(self, addr, value, tmp_reg=3, size=32, position=0):
		if size != 32:
			self._read_mem(tmp_reg, addr, position=position)
			self.lines.append('pand xmm%d, %s' % (tmp_reg, self._m128_flag4(position, -self._ff_flag[size], self._ff_flag[32])))
		else:
			self.lines.append('pxor xmm%d, xmm%d' % (tmp_reg, tmp_reg))
		self.lines.append('pxor xmm%d, %s' % (tmp_reg, self._m128_flag4(position, yes=value)))
		if position != 0:
			self.lines.append('pshufd xmm%d, xmm%d, %d' % (tmp_reg, tmp_reg, self._flag_pshufd(0, position)))
		self.lines.append('movss [0x%x], xmm%d' % tmp_reg)
	
	# read a [8, 16, 32] bit "emulated" gpr to the given xmm register's low 32bits
	def _read_emugpr_xmm(self, gpr, xmm=0, size=32):
		# TODO: 8/16bit support
		
		self.lines.append('pshufd xmm%d, %s, %d' % (xmm, self._xmm_gpr_index(gpr), self._flag_pshufd(3, gpr & 3)))
		if size == 8:
			self.lines.append('pand xmm%d, %s' % (xmm, self._m128_flag16(0, yes=self._ff_flag[size])))
		elif size == 16:
			self.lines.append('pand xmm%d, %s' % (xmm, self._m128_flag8(0, yes=self._ff_flag[size])))
		elif size == 32:
			self.lines.append('pand xmm%d, %s' % (xmm, self._m128_flag4(0, yes=self._ff_flag[size])))
	
	# write a [8, 16, 32] bit "emulated" gpr to the given xmm register's low 32bits
	def _write_emugpr_xmm(self, gpr, xmm=0, size=32):
		# TODO: 8/16bit support
		
		# zero the register out
		self.lines.append('pand %s, %s' % (self._xmm_gpr_index(gpr), self._m128_flagsize(gpr & 3, no=self._ff_flag[size], size=size)))
		
		# make sure the value is in the correct dword
		if gpr & 3: self.lines.append('pshufd xmm%d, xmm%d, %d' % (xmm, xmm, self._flag_pshufd(gpr & 3, 0)))
		
		# zero everything out for the source operand
		self.lines.append('pand xmm%d, %s' % (xmm, self._m128_flag4(gpr & 3, yes=self._ff_flag[size])))
		
		# write the new value
		self.lines.append('por %s, xmm%d' % (self._xmm_gpr_index(gpr), xmm))
		
		#print '\n'.join(self.lines)
	
	def _read_memory_xmm(self, addr, xmm=0, size=32):
		# TODO: 8/16bit support
		
		self.lines.append('movd xmm%d, dword ptr [0x%08x]' % (xmm, addr))
		
	def _write_memory_xmm(self, addr, xmm=0, size=32):
		# TODO: 8/16bit support
		
		self.lines.append('movd dword ptr [0x%08x], xmm%d' % (addr, xmm))
	
	def _read_value_xmm(self, operand, xmm=0):
		op = self.dis.operands[operand]
		if op.type == OPERAND_REGISTER:
			self._read_emugpr_xmm(op.index & 7, xmm=xmm, size=op.size)
		elif op.type == OPERAND_IMMEDIATE:
			self.lines.append('movapd xmm%d, %s' % (xmm, self._m128([op.value,0,0,0])))
		elif op.type == OPERAND_ABSOLUTE_ADDRESS:
			self._read_memory_xmm(op.disp, xmm=xmm, size=op.size)
		elif op.type == OPERAND_MEMORY:
			# TODO: evaluate memory address expression
			self = self
	
	def _write_value_xmm(self, operand, xmm=0):
		op = self.dis.operands[operand]
		if op.type == OPERAND_REGISTER:
			self._write_emugpr_xmm(op.index & 7, xmm=xmm, size=op.size)
		elif op.type == OPERAND_IMMEDIATE:
			raise Exception('dafuq')
		elif op.type == OPERAND_ABSOLUTE_ADDRESS:
			self._write_memory_xmm(op.disp, xmm=xmm, size=op.size)
		elif op.type == OPERAND_MEMORY:
			# TODO: evaluate memory address expression
			self = self
	
	def _encode_nop(self):
		# do nothing
		self
	
	def _encode_xor(self):
		self._read_value_xmm(0)
		self._read_value_xmm(1, 1)
		self.lines.append('pxor xmm0, xmm1')
		self._write_value_xmm(0)
	
	def _encode_or(self):
		self._read_value_xmm(0)
		self._read_value_xmm(1, 1)
		self.lines.append('por xmm0, xmm1')
		self._write_value_xmm(0)
	
	def _encode_and(self):
		self._read_value_xmm(0)
		self._read_value_xmm(1, 1)
		self.lines.append('pand xmm0, xmm1')
		self._write_value_xmm(0)
	
	def _encode_mov(self):
		self._read_value_xmm(1)
		self._write_value_xmm(0)
	
	def _encode_add(self):
		self._read_value_xmm(0)
		self._read_value_xmm(1, 1)
		self.lines.append('paddd xmm0, xmm1')
		self._write_value_xmm(0)
	
	def _encode_sub(self):
		self._read_value_xmm(0)
		self._read_value_xmm(1, 1)
		self.lines.append('psubd xmm0, xmm1')
		self._write_value_xmm(0)
	
	def _encode_push(self):
		# esp is the first dword in the xmm7 register
		self.lines.append('psubd xmm7, %s' % self._m128([4, 0, 0, 0]))
		
		self._read_value_xmm(0)
		self._read_emugpr_xmm(assemble.ESP, 1)
		self.lines.append('movd eax, xmm1')
		self.lines.append('movd dword [eax], xmm0')
	
	def _encode_pop(self):
		self._read_value_xmm(0)
		self._read_emugpr_xmm(assemble.ESP, 1)
		self.lines.append('movd eax, xmm1')
		self.lines.append('movd xmm0, dword [eax]')
		self._write_value_xmm(0)
		
		# esp is the first dword in the xmm7 register
		self.lines.append('paddd xmm7, %s' % self._m128([4, 0, 0, 0]))
	
	def _encode_inc(self):
		self._read_value_xmm(0)
		self.lines.append('paddd xmm0, %s' % self._m128([1, 0, 0, 0]))
		self._write_value_xmm(0)
		
	def _encode_dec(self):
		self._read_value_xmm(0)
		self.lines.append('psubd xmm0, %s' % self._m128([1, 0, 0, 0]))
		self._write_value_xmm(0)
	
	def _encode_not(self):
		self._read_value_xmm(0)
		self.lines.append('pxor xmm0, %s' % self._m128([0xffffffff, 0, 0, 0]))
		self._write_value_xmm(0)
	
	def _encode_neg(self):
		self._read_value_xmm(0)
		self.lines.append('pxor xmm1, xmm1')
		self.lines.append('psubd xmm1, xmm0')
		self._write_value_xmm(0, 1)
	
	def _encode_xchg(self):
		self._read_value_xmm(0)
		self._read_value_xmm(1, 1)
		self._write_value_xmm(1, 0)
		self._write_value_xmm(0, 1)
	
	def _encode_leave(self):
		# leave = mov esp, ebp ; pop ebp
		self.lines += enc_apply('8be5')
		self.lines += enc_apply('5d')
	
	def _encode_ret(self):
		# ret = pop eip
		
		# we encode as pop eax ; jmp eax
		self._read_emugpr_xmm(assemble.ESP)
		self.lines.append('movd eax, xmm0')
		
		# esp is the first dword in the xmm7 register
		self.lines.append('paddd xmm7, %s' % self._m128([4, 0, 0, 0]))
		
		# jump to the address
		self.lines.append('jmp dword [eax]')
if __name__ == '__main__':
	lines = sys.stdin.readlines()
	code = assemble.assemble(lines)
	print binascii.hexlify(code)
