"""
ssexy v0.1    (C) 2012 Jurriaan Bremer

"""

import sys, pefile, distorm3

# config stores some configuration, as well as API definitions (ie, win32
# api's are like _MessageBox@4..)
import config

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

    # apply config to the imports, if its not in the configuration, just
    # prepend the api with an underscore, the way gcc likes it.
    imports = dict((k, config.apis[v] if v in config.apis else '_' + v)
        for k, v in imports.items())

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

        # remove any addresses that are from within the current section
        for i in xrange(len(addresses)):
            if addresses[i] >= pe.OPTIONAL_HEADER.ImageBase + \
                    section.VirtualAddress and addresses[i] < \
                    pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + \
                    len(section.get_data()):
                del addresses[i]

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

    program = ['.file "ssexy.c"', '.intel_syntax noprefix']

    # we walk over each section, if a reference to this section has been found
    # then we will dump the entire section as bytecode.. with matching labels
    for section in pe.sections:
        base = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        data = section.get_data()
        addr = set(range(base, base + len(data))).intersection(addresses)
        if addr:
            # create a header for this section
            program.append('.section %s,"dr"' % section.Name.strip('\x00'))

            # for now we do it the easy way.. one line and label per byte, lol
            for addr in xrange(len(data)):
                program.append('__lbl_%08x: .byte 0x%02x' % (base + addr,
                    ord(data[addr])))

            # empty line..
            program.append('')

    # time to define 'main'
    program.append('.globl _main')

    # append each instruction
    for instr in instructions.instructions:
        # for OEP we add an additional 'main' label
        if hasattr(instr, 'address') and instr.address == \
                pe.OPTIONAL_HEADER.ImageBase + \
                pe.OPTIONAL_HEADER.AddressOfEntryPoint:
            program.append('_main:')
        # if this is an label, we want a colon as postfix
        if isinstance(instr, pyasm2.Label):
            program.append(str(instr) + ':')
        else:
            program.append(str(instr))

    print '\n'.join(program)
