"""

Translates the x86 General Purpose Instructions into SSE Instructions.

Unfortunately the current implementations only allows 1:1 translation, newer
versions should support translation of multiple instructions at once.

xmm0 = input
xmm1 = output
xmm2 = intermediate (used in handlers that also call `core' apis)
xmm3 = temporary (used in `core' apis)

"""
import sys

sys.path.append('pyasm2')

# one of the main reasons translation is done in a seperate module
from pyasm2 import *

def translate(instr):
    """TranslateCeption?"""
    return Translator(instr).translate()

class Translater:
    def __init__(self, instr, m128s, m32s):
        self.instr = instr
        self.m128s = m128s
        self.m32s = m32s
        self.block = block()
        self._reg_index = 0

    def m128(self, *val):
        """Creates a m128 and returns its label."""
        length = len(self.m128s)
        semi_addr = 0xff000000 + length
        self.m128s.append(('__lbl_%08x: ' + '.long %s ; ' * 4) %
            tuple([semi_addr] + map(str, val)))
        return MemoryAddress(size=128,
            disp=Immediate(value=semi_addr, addr=True))

    def m32(self, value):
        """Creates a m32 and returns its label."""
        length = len(self.m32s)
        semi_addr = 0xfe000000 + length
        value = value if value is not None else 0
        self.m32s.append('__lbl_%08x: .long %s' % (semi_addr, str(value)))
        return MemoryAddress(size=32,
            disp=Immediate(value=semi_addr, addr=True))

    def m128_field(self, field, value, other=0):
        """Returns an m128 with `value' in `field', other field become 0."""
        assert field in xrange(4)

        args = (value if x == field else other for x in xrange(4))
        return self.m128(*args)

    def usable_gpr(self):
        """In order to load xmm registers, GPRs are needed, but which one?"""
        # simply iterate through them all.
        ret = gpr.register32[self._reg_index % 8]
        self._reg_index += 1
        return ret

    def mem_eval(self, dst, src):
        """Evaluate a Memory Address `src' into XMM Register `dst'."""
        assert isinstance(src, mem)
        assert isinstance(dst, xmm)

        # if `src' is a memory address of which `reg1' *or* `reg2' is set,
        # then we have to evaluate this memory address
        if src.reg1 or src.reg2:
            # load the displacement
            self.block += movd(xmm3, self.m32(src.disp))

            # if `reg1' is set, add it
            if src.reg1:
                self.read_gpr(xmm2, src.reg1)
                self.block += paddd(xmm3, xmm2)

            # if `reg2' is set, add it
            if src.reg2:
                self.read_gpr(xmm2, src.reg2)
                self.block += pslld(xmm2, {1: 0, 2: 1, 4: 2, 8: 3}[src.mult])
                self.block += paddd(xmm3, xmm2)

            # store the value into `dst'
            self.block += movups(dst, xmm3)
        else:
            # there is only a displacement
            self.block += movd(dst, self.m32(src.disp))

    def xmm_load(self, dst, src):
        """Load xmm register `dst' with anything inside `src'."""
        assert dst.size == 128

        if isinstance(src, mem):
            self.mem_eval(xmm3, src)
            src = xmm3

        # now read the value.
        if src.size == 128:
           self.block += movups(dst, src)
        elif src.size == 32:
            gpr = self.usable_gpr()
            self.block += mov(gpr, src)
            self.block += movd(dst, gpr)
        else:
            gpr = self.usable_gpr()
            self.block += movzx(gpr, src)
            self.block += movd(dst, gpr)

    def memory_write(self, dst, src):
        """Write `src' to `dst'."""
        # resolve the address in `dst'
        assert isinstance(dst, mem)

        self.mem_eval(xmm3, dst)
        gpr1 = self.usable_gpr()
        self.block += movd(gpr1, xmm3)
        dst = mem(size=dst.size, reg1=gpr1)

        if isinstance(src, gpr):
            self.read_gpr(xmm0, src)
            src = xmm0
        elif isinstance(src, mem):
            self.xmm_load(xmm0, src)
            src = xmm0

        # register to an address or similar
        if dst.size in (8, 16, 32) and (dst.size == src.size or
                isinstance(src, imm)):
            self.block += mov(dst, src)

        # from an xmm register to an address
        elif dst.size == 32 and src.size == 128:
            gpr2 = self.usable_gpr()
            self.block += movd(gpr2, src)
            self.block += mov(dst, gpr2)

        else:
            raise Exception('dst: %d, src: %d' % (dst.size, src.size))

    def read_gpr(self, dst, src):
        """Read a General Purpose Register into `dst'."""
        assert isinstance(src, gpr)

        reg = xmm6 if src.index < 4 else xmm7
        if isinstance(dst, xmm):
            self.block += pshufd(dst, reg, src.index & 3)

        elif isinstance(dst, gpr):
            self.block += pshufd(xmm3, reg, src.index & 3)
            self.block += movd(dst, xmm3)

        else:
            assert isinstance(dst, mem)

            # evaluate the address in `dst'
            self.mem_eval(xmm2, dst)
            gpr1 = self.usable_gpr()
            self.block += movd(gpr, xmm2)
            dst = mem(size=dst.size, reg1=gpr1)

            # read the gpr
            self.block += pshufd(xmm3, reg, src.index & 3)

            f = mov if dst.size == 32 else movzx

            # write the gpr to `dst'
            gpr2 = self.usable_gpr()
            self.block += movd(gpr2, xmm3)
            self.block += f(dst, gpr2)

    def write_gpr(self, dst, src):
        """Write `src' to a General Purpose Register `dst'."""
        assert isinstance(dst, gpr)

        if isinstance(src, mem):
            self.mem_eval(xmm3, src)
            src = xmm3
        elif isinstance(src, gpr):
            # TODO 8/16bit
            self.block += movd(xmm3, src)
            src = xmm3
        elif isinstance(src, imm):
            self.block += movd(xmm3, self.m32(src))

        if isinstance(src, xmm):
            reg = xmm6 if dst.index < 4 else xmm7
            self.block += pshufd(src, src, 0)
            self.block += pand(src, self.m128_field(dst.index & 3, -1))
            self.block += pand(reg, self.m128_field(dst.index & 3, 0, -1))
            self.block += pxor(reg, src)
        else:
            raise Exception('wut?')

    def add_gpr(self, dst, val):
        """Add `val' to General Purpose Register `dst'."""
        self.read_gpr(xmm3, dst)
        self.block += paddd(xmm3, self.m128(val, 0, 0, 0))
        self.write_gpr(dst, xmm3)

    def sub_gpr(self, dst, val):
        """Subtract `val' from General Purpose Register `dst'."""
        self.read_gpr(xmm3, dst)
        self.block += psubd(xmm3, self.m128(val, 0, 0, 0))
        self.write_gpr(dst, xmm3)

    def read_operand(self, dst, src):
        """Read value at operand `src' into XMM Register `dst'."""
        if isinstance(src, gpr):
            self.read_gpr(dst, src)
        else:
            assert isinstance(src, (imm, mem))

            self.xmm_load(dst, src)

    def write_operand(self, dst, src):
        """Write value `src' into anything specified by operand `dst'."""
        if isinstance(dst, gpr):
            self.write_gpr(dst, src)
        else:
            assert isinstance(dst, mem)

            self.memory_write(dst, src)

    def translate(self):
        f = getattr(self, 'encode_' + self.instr.mnemonic(), None)
        if not f:
            sys.stderr.write('Cannot encode %s\n' % self.instr.mnemonic())
            return block(self.instr)

        f()
        return self.block

    def t(self, *instructions):
        """Translate a sequence of instructions."""
        for x in instructions:
            self.instr = x
            self.translate()

    def encode_push(self):
        self.sub_gpr(esp, 4)
        self.memory_write(dword[esp], self.instr.op1)

    def encode_mov(self):
        self.read_operand(xmm0, self.instr.op2)
        self.write_operand(self.instr.op1, xmm0)
