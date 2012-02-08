import sys, binascii
from assemble import assemble
from distorm3 import OPERAND_REGISTER, OPERAND_IMMEDIATE, OPERAND_MEMORY, OPERAND_ABSOLUTE_ADDRESS

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
			if dis.operands[0].type == OPERAND_REGISTER:
				self.reg_index1 = dis.operands[0].index & 7
				self.xmm_index1 = dis.operands[0].index & 3
				self.xmm_reg1 = self._xmm_gpr_index(self.reg_index1)
				self.size1 = self.dis.operands[0].size
		
		if len(dis.operands) > 1:
			if dis.operands[1].type == OPERAND_REGISTER:
				self.reg_index2 = dis.operands[1].index & 7
				self.xmm_index2 = dis.operands[1].index & 3
				self.xmm_reg2 = self._xmm_gpr_index(self.reg_index2)
				self.size2 = self.dis.operands[1].size
	
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
			self.lines.append('.align 16')
			self.lines.append('m128_%d:' % len(Enc._labels))
			self.lines.append('.long 0x%x, 0x%x, 0x%x, 0x%x' % tuple(val))
			self.lines.append('m128_%d_end:' % len(Enc._labels))
			Enc._labels[str(val)] = 'm128_%d' % len(Enc._labels)
		return Enc._labels[str(val)]
	
	# construct a 16byte xmm value from 4 dwords
	def _m128_flag4(self, index, yes, no=0):
		val = [no for i in range(4)]
		val[index] = yes
		return self._m128(val)
	
	# construct a 16byte xmm value from 8 words
	def _m128_flag8(self, index, yes, no=0):
		val = [no for i in range(8)]
		val[index * 2] = yes
		return self._m128([(val[i] + (val[i+1] << 16)) for i in xrange(0, 8, 2)])
	
	# construct a 16byte xmm value from 16 bytes
	def _m128_flag16(self, index, yes, no=0):
		val = [no for i in range(16)]
		val[index * 4] = yes
		return self._m128([reduce(lambda x, y: x * 256 + y, val[i:i+4][::-1]) for i in xrange(0, 16, 4)])
	
	# calculate the flag for pshufd instruction
	def _flag_pshufd(self, index, value, flags=[0,1,2,3]):
		flags[index & 3] = value & 3
		return reduce(lambda x, y: x * 4 + y, flags)
	
	# read a 8bit, 16bit or 32bit integer from a memory address, optionally give it a special position
	def _read_mem(self, reg, addr, size=32, position=0):
		self.lines.append('movss xmm%d, [0x%x]' % (reg, addr))
		if size != 32:
			self.lines.append('pand xmm%d, %s' % (reg, self._m128([self._ff_flag[size], 0, 0, 0])))
		if position != 0:
			self.lines.append('pshufd xmm%d, xmm%d, %d' % (reg, reg, self._flag_pshufd(position, 0, [3,3,3,3])))
	
	# write a 8bit, 16bit or 32bit value to an address
	def _write_mem(self, addr, value, tmp_reg=3, size=32, position=0):
		if size != 32:
			self._read_mem(tmp_reg, addr, position=position)
			self.lines.append('pand xmm%d, %s' % (tmp_reg, self._m128_flag4(position, ~self._ff_flag[size], self._ff_flag[32])))
		else:
			self.lines.append('pxor xmm%d, xmm%d' % (tmp_reg, tmp_reg))
		self.lines.append('pxor xmm%d, %s' % (tmp_reg, self._m128_flag4(position, value, 0)))
		if position != 0:
			self.lines.append('pshufd xmm%d, xmm%d, %d' % (tmp_reg, tmp_reg, self._flag_pshufd(0, position, [3,3,3,3])))
		self.lines.append('movss [0x%x], xmm%d' % tmp_reg)
	
	def _encode_xor(self):
		# xor reg, xxx
		if self.dis.operands[0].type == OPERAND_REGISTER:
			# xor reg_a, reg_b
			if self.dis.operands[1].type == OPERAND_REGISTER:
				# xor reg_a, reg_a
				if self.reg_index1 == self.reg_index2:
					flag = {
						8:  lambda self: self._m128_flag16(self.xmm_index1, 0, self._ff_flag[8]),
						16: lambda self: self._m128_flag8(self.xmm_index1, 0, self._ff_flag[16]),
						32: lambda self: self._m128_flag4(self.xmm_index1, 0, self._ff_flag[32])
					}[self.size1](self)
					self.lines.append('pand %s, %s' % (self.xmm_reg1, flag))
			# xor reg, imm
			elif self.dis.operands[1].type == OPERAND_IMMEDIATE:
				flag = self._m128_flag4(self.xmm_index1, self.dis.operands[1].value, 0)
				self.lines.append('pxor %s, %s' % (self.xmm_reg1, flag))
	
	def _encode_mov(self):
		# mov reg, xxx
		if self.dis.operands[0].type == OPERAND_REGISTER:
			# mov reg_a, reg_b
			if self.dis.operands[1].type == OPERAND_REGISTER:
				# both registers are stored in the same xmm register
				if self.xmm_index1 == self.xmm_index2:
					if self.size1 == 32:
						# duplicate the source 32bit to the destination 32bit
						self.lines.append('pshufd %s, %s, %d' % (self.xmm_reg1, self.xmm_reg2, self._flag_pshufd(self.xmm_index1, self.xmm_index2)))
				# one register remains in xmm6, the other in xmm7
				else:
					self.lines.append('pand %s, %s' % (self.xmm_reg1, self._m128_flag4(self.xmm_index1, 0, self._ff_flag[size])))
					self.lines.append('pshufd xmm0, %s, %d' % (self.xmm_reg2, self._flag_pshufd(self.xmm_index1, self.xmm_index2)))
					self.lines.append('pand %s, %s' % (self.xmm_reg2, self._m128_flag4(self.xmm_index2, self._ff_flag[size], 0)))
					self.lines.append('pxor %s, %s' % (self.xmm_reg1, self.xmm_reg2))
			# mov reg, imm
			elif self.dis.operands[1].type == OPERAND_IMMEDIATE:
				self.lines.append('pand %s, %s' % (self.xmm_reg1, self._m128_flag4(self.xmm_index1, ~self._ff_flag[size], self._ff_flag[32])))
				self.lines.append('pxor %s, %s' % (self.xmm_reg1, self._m128_flag4(self.xmm_index1, self.dis.operands[1].value, 0)))

if __name__ == '__main__':
	lines = sys.stdin.readlines()
	code = assemble(lines)
	print binascii.hexlify(code)