import sys, binascii
from assemble import assemble
from distorm3 import OPERAND_REGISTER, OPERAND_IMMEDIATE, OPERAND_MEMORY, OPERAND_ABSOLUTE_ADDRESS

class Enc:
	_labels = {}
	_ff_flag = {8: 0xff, 16: 0xffff, 32: 0xffffffff}
	
	def __init__(self, dis):
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
		
		if len(dis.operands) > 1:
			if dis.operands[1].type == OPERAND_REGISTER:
				self.reg_index2 = dis.operands[1].index & 7
				self.xmm_index2 = dis.operands[1].index & 3
				self.xmm_reg2 = self._xmm_gpr_index(self.reg_index2)
	
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
	def _m128_flag4(self, index, yes, no):
		val = [no for i in range(4)]
		val[index] = yes
		return self._m128(val)
	
	# construct a 16byte xmm value from 8 words
	def _m128_flag8(self, index, yes, no):
		val = [no for i in range(8)]
		val[index * 2] = yes
		return self._m128([(val[i] + (val[i+1] << 16)) for i in xrange(0, 8, 2)])
	
	# construct a 16byte xmm value from 16 bytes
	def _m128_flag16(self, index, yes, no):
		val = [no for i in range(16)]
		val[index * 4] = yes
		return self._m128([reduce(lambda x, y: x * 256 + y, val[i+4:i:-1]) for i in xrange(0, 16, 4)])
	
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
					}[self.dis.operands[0].size](self)
					self.lines.append('pand %s, %s' % (self.xmm_reg1, flag))
			# xor reg, imm
			elif self.dis.operands[1].type == OPERAND_IMMEDIATE:
				flag = self._m128_flag4(self.xmm_index1, self.dis.operands[1].value, 0)
				self.lines.append('pxor %s, %s' % (self.xmm_reg1, flag))

if __name__ == '__main__':
	lines = sys.stdin.readlines()
	code = assemble(lines)
	print binascii.hexlify(code)
