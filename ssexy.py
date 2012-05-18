import sys, pefile, distorm3

# oboy this is ugly
sys.path.append('pyasm2')
import pyasm2

def translate(instr):
    """Function to translate distorm3 into pyasm2."""
    # try to resolve this instruction
    if hasattr(pyasm2, instr.mnemonic.lower()):
        cls = getattr(pyasm2, instr.mnemonic.lower())
    # some instructions collide with python keywords, they have an
    # underscore postfix
    elif hasattr(pyasm2, instr.mnemonic.lower() + '_'):
        cls = getattr(pyasm2, instr.mnemonic.lower() + '_')
    # unfortunately, this instruction has not been implemented
    else:
        raise Exception('Unknown instruction: %s' % instr.mnemonic)

    def reg(name):
        """Small wrapper to return a Register."""
        if isinstance(name, int):
            name = distorm3.Registers[name]
        if not hasattr(pyasm2, name.lower()):
            raise Exception('Unknown register: %s' % op.name)
        return getattr(pyasm2, name.lower())

    operands = []

    for op in instr.operands:
        if op.type == distorm3.OPERAND_IMMEDIATE:
            operands.append(op.value)

        elif op.type == distorm3.OPERAND_REGISTER:
            operands.append(reg(op.name))

        elif op.type == distorm3.OPERAND_MEMORY:
            base = None if op.base is None else reg(op.base)
            index = None if op.index is None else reg(op.index)
            mult = None if not op.scale else op.scale
            disp = None if not op.disp else op.disp

            operands.append(pyasm2.MemoryAddress(size=op.size, reg1=base,
                reg2=index, mult=mult, disp=disp))

        elif op.type == distorm3.OPERAND_ABSOLUTE_ADDRESS:
            operands.append(pyasm2.MemoryAddress(size=op.size, disp=op.disp))

    # create an instruction based on the operands
    ret = cls(*operands)

    # store the address and length of this instruction
    ret.address = instr.address
    ret.length = instr.size
    return ret

if __name__ == '__main__':
    sys.stderr.write('ssexy v0.1    (C) 2012 Jurriaan Bremer\n')
    if len(sys.argv) != 2:
        print 'Usage: %s <binary>' % sys.argv[0]
        exit(0)

    # load the pe file
    pe = pefile.PE(sys.argv[1])

    # make a addr: value dictionary for all imports
    imports = dict((x.address, x.name) for e in pe.DIRECTORY_ENTRY_IMPORT
        for x in e.imports)

    # dictionary with addr: value where addr is the address of the
    # `jmp dword [thunk address]' and value the name of this import.
    iat_label = {}

    # a set of all relocations
    relocs = set([(pe.OPTIONAL_HEADER.ImageBase + y.rva)
        for x in pe.DIRECTORY_ENTRY_BASERELOC for y in x.entries])

    # a list of addresses that were used.
    addresses = []

    instructions = pyasm2.block()

    # walk each section, find those that are executable and disassemble those
    for section in filter(lambda x: x.IMAGE_SCN_MEM_EXECUTE, pe.sections):
        g = distorm3.DecomposeGenerator(pe.OPTIONAL_HEADER.ImageBase +
            section.VirtualAddress, section.get_data(), distorm3.Decode32Bits)
        for instr in g:
            # useless instruction?
            if str(instr) in ('NOP', 'ADD [EAX], AL', 'LEA ESI, [ESI]') or \
                    str(instr)[:2] == 'DB':
                continue

            # a jump to one of the imports?
            if instr.mnemonic == 'JMP' and instr.operands[0].type == \
                    distorm3.OPERAND_ABSOLUTE_ADDRESS and \
                    instr.operands[0].disp in imports:
                iat_label[instr.address] = imports[instr.operands[0].disp]
                continue

            # quite hackery, but when the jumps with thunk address have been
            # processed, we can be fairly sure that there will be no (legit)
            # code anymore.
            if len(iat_label):
                break

            # convert the instruction from distorm3 format to pyasm2 format.
            instr = translate(instr)

            # we create the block already here, otherwise our `labelnr' is
            # not defined.
            block = pyasm2.block(pyasm2.Label(hex(instr.address)), instr)

            # now we check if this instruction has a relocation inside it
            # not a very efficient way, but oke.
            reloc = instr.length > 4 and relocs.intersection(range(
                instr.address, instr.address + instr.length - 3))
            if reloc:
                # TODO support for two relocations in one instruction
                # (displacement *and* immediate)
                reloc = reloc.pop()
                # there is only one operand, that's easy
                if not instr.op2:
                    print instr.op1
                # if the second operand is an immediate and the relocation is
                # in the last four bytes of the instruction, then this
                # immediate is the reloc. Otherwise, if the second operand is
                # a memory address, then it's the displacement.
                elif isinstance(instr.op2, pyasm2.Immediate) and reloc == \
                        instr.address + instr.length - 4:
                    # keep this address
                    addresses.append(int(instr.op2))
                    # make a label from this address
                    instr.op2 = pyasm2.Label(hex(int(instr.op2)))
                elif isinstance(instr.op2, pyasm2.MemoryAddress) and \
                        reloc == instr.address + instr.length - 4:
                    print 'reloc in op2 memaddr', str(instr.op2)
                # the relocation is not inside the second operand, it must be
                # inside the first operand after all.
                elif isinstance(instr.op1, pyasm2.MemoryAddress):
                    print 'reloc in op1 memaddr', str(instr.op1)
                elif isinstance(instr.op1, pyasm2.Immediate):
                    print 'reloc in op1 imm', instr.op1
                else:
                    print 'Invalid Relocation!'

            instructions += block

    # walk over each instruction, if it has references, we update them
    for instr in instructions.instructions:
        # we can skip labels
        if isinstance(instr, pyasm2.Label):
            continue

        # check for references to imports
        if isinstance(instr, pyasm2.RelativeJump):
            # not very good, but for now (instead of checking relocs) we check
            # if the index is in the iat tabel..
            if instr.lbl.index in iat_label:
                instr.lbl.index = iat_label[instr.lbl.index]
                instr.lbl.prepend = False
            continue

        # check for references to data
        elif hasattr(instr, 'operand1') and \
                isinstance(instr.operand1, pyasm2.Label):
            print instr.operand1
        elif hasattr(instr, 'operand2') and \
                isinstance(instr.operand2, pyasm2.Label):
            print instr.operand2

    print instructions, [(hex(x), y) for x, y in iat_label.items()]
