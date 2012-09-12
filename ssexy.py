"""
ssexy v0.1    (C) 2012 Jurriaan Bremer

"""

import sys, distorm3

# config stores some configuration, as well as API definitions (ie, win32
# api's are like _MessageBox@4..)
import config

# oboy this is ugly
sys.path.append('pyasm2')
import pyasm2

import translate

def distorm3_to_pyasm2(instr):
    """Function to translate distorm3 into pyasm2."""
    # try to resolve this instruction
    if hasattr(pyasm2, instr.mnemonic.lower()):
        cls = getattr(pyasm2, instr.mnemonic.lower())
    # some instructions collide with python keywords, they have an
    # underscore postfix
    elif hasattr(pyasm2, instr.mnemonic.lower() + '_'):
        cls = getattr(pyasm2, instr.mnemonic.lower() + '_')
    # exception for these instructions, as we have to get the size of the
    # instruction from the operands..
    elif instr.mnemonic.lower() in ['movs', 'cmps']:
        size = 'b' if instr.operands[0].size == 8 else 'd'
        cls = getattr(pyasm2, instr.mnemonic.lower() + size)
        # remove the operands from this opcode, because we already give the
        # size in the opcode.
        instr.operands = ()
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
            if instr.flowControl in ['FC_CALL', 'FC_UNC_BRANCH',
                    'FC_CND_BRANCH']:
                operands.append('%08x' % op.value)
            else:
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

    #sys.stderr.write(str(instr) + '\n')

    # create an instruction based on the operands
    ret = cls(*operands)

    # rep prefix
    if 'FLAG_REP' in instr.flags:
        ret.rep = True

    # store the address and length of this instruction
    ret.address = instr.address
    ret.length = instr.size
    return ret

def ssexy_win32(fname):
    import pefile

    # load the pe file
    pe = pefile.PE(fname)

    # make a addr: value dictionary for all imports
    imports = dict((x.address, x.name or (e.dll.lower(), x.ordinal))
        for e in pe.DIRECTORY_ENTRY_IMPORT for x in e.imports)

    # apply config to the imports, if its not in the configuration, just
    # prepend the api with an underscore, the way gcc likes it.
    imports = dict((k, config.apis[v] if v in config.apis else
        config.Api('_' + v)) for k, v in imports.items())

    # dictionary with addr: value where addr is the address of the
    # `jmp dword [thunk address]' and value the name of this import.
    iat_label = {}

    # a set of all relocations
    relocs = set([(pe.OPTIONAL_HEADER.ImageBase + y.rva)
        for x in pe.DIRECTORY_ENTRY_BASERELOC for y in x.entries])

    # a list of addresses that were used.
    addresses = []

    # a list of all m128 values we use
    m128s = []

    # a list of all dword values we use
    m32s = []

    instructions = pyasm2.block()

    # walk each section, find those that are executable and disassemble those
    for section in filter(lambda x: x.IMAGE_SCN_MEM_EXECUTE, pe.sections):
        g = distorm3.DecomposeGenerator(pe.OPTIONAL_HEADER.ImageBase +
            section.VirtualAddress, section.get_data(), distorm3.Decode32Bits)
        for instr in g:
            # useless instruction?
            if str(instr) in ('NOP', 'ADD [EAX], AL', 'LEA ESI, [ESI]',
                        'INT 3') or str(instr)[:2] == 'DB':
                continue

            # a jump to one of the imports?
            #if instr.mnemonic == 'JMP' and instr.operands[0].type == \
            #        distorm3.OPERAND_ABSOLUTE_ADDRESS and \
            #        instr.operands[0].disp in imports:
            #    iat_label[instr.address] = imports[instr.operands[0].disp]
            #    continue

            # quite hackery, but when the jumps with thunk address have been
            # processed, we can be fairly sure that there will be no (legit)
            # code anymore.
            #if len(iat_label):
            #    break

            #print str(instr)

            #print str(instr)

            # convert the instruction from distorm3 format to pyasm2 format.
            instr = distorm3_to_pyasm2(instr)

            # we create the block already here, otherwise our `labelnr' is
            # not defined.
            #block = pyasm2.block(pyasm2.Label('%08x' % instr.address), instr)
            offset_flat = None
            addr = instr.address

            # now we check if this instruction has a relocation inside it
            # not a very efficient way, but oke.
            reloc = instr.length > 4 and relocs.intersection(range(
                instr.address, instr.address + instr.length - 3))
            if reloc:
                # make an immediate with `addr' set to True
                enable_addr = lambda x: Immediate(int(x), addr=True)

                # TODO support for two relocations in one instruction
                # (displacement *and* immediate)
                reloc = reloc.pop()
                # there is only one operand, that's easy
                if not instr.op2:
                    #sys.stderr.write('reloc in op1 %s??\n' % instr.op1)
                    if isinstance(instr.op1, pyasm2.MemoryAddress):
                        # special occassion, this memory addres is an import
                        if instr.op1.reg1 is None and \
                                instr.op1.reg2 is None and \
                                int(instr.op1.disp) in imports:
                            instr.op1 = imports[int(instr.op1.disp)]
                        else:
                            addresses.append(int(instr.op1.disp))
                            # change the displacement to a label
                            #instr.op1 = str(instr.op1).replace('0x',
                            #    '__lbl_00')
                            instr.op1 = enable_addr(instr.op1)
                    elif isinstance(instr.op1, pyasm2.Immediate):
                        addresses.append(int(instr.op1))
                        offset_flat = int(instr.op1)
                        #instr.op1 = str(instr.op1).replace('0x',
                        #    'offset flat:__lbl_00')
                # if the second operand is an immediate and the relocation is
                # in the last four bytes of the instruction, then this
                # immediate is the reloc. Otherwise, if the second operand is
                # a memory address, then it's the displacement.
                elif isinstance(instr.op2, pyasm2.Immediate) and reloc == \
                        instr.address + instr.length - 4:
                    # keep this address
                    addresses.append(int(instr.op2))
                    # make a label from this address
                    # TODO: fix this horrible hack
                    offset_flat = int(instr.op2)
                    #instr.op2 = pyasm2.Label('offset flat:__lbl_%08x' %
                    #    int(instr.op2), prepend=False)
                elif isinstance(instr.op2, pyasm2.MemoryAddress) and \
                        reloc == instr.address + instr.length - 4:
                    addresses.append(int(instr.op2.disp))
                    # change the displacement to a label
                    instr.op2 = enable_addr(instr.op2)
                    #instr.op2 = str(instr.op2).replace('0x', '__lbl_00')
                    #sys.stderr.write('reloc in op2 memaddr %s\n' %
                    #    str(instr.op2))
                # the relocation is not inside the second operand, it must be
                # inside the first operand after all.
                elif isinstance(instr.op1, pyasm2.MemoryAddress):
                    addresses.append(int(instr.op1.disp))
                    instr.op1 = enable_addr(instr.op1)
                    #instr.op1 = str(instr.op1).replace('0x', '__lbl_00')
                    #sys.stderr.write('reloc in op1 memaddr %s\n' %
                    #    str(instr.op1))
                elif isinstance(instr.op1, pyasm2.Immediate):
                    addresses.append(int(instr.op1))
                    instr.op1 = enable_addr(instr.op1)
                    #instr.op1 = '__lbl_%08x' % int(instr.op1)
                    #sys.stderr.write('reloc in op1 imm %s\n' % instr.op1)
                else:
                    sys.stderr.write('Invalid Relocation!\n')

            instr = translate.Translater(instr, m128s, m32s).translate()
            if offset_flat:
                encode_offset_flat = lambda x: str(x).replace('0x',
                    'offset flat:__lbl_') if isinstance(x, (int, long,
                    pyasm2.imm)) and int(x) == offset_flat or isinstance(x,
                    pyasm2.mem) and x.disp == offset_flat else x

                if isinstance(instr, pyasm2.block):
                    for x in instr.instructions:
                        x.op1 = encode_offset_flat(x.op1)
                        x.op2 = encode_offset_flat(x.op2)
                else:
                    x.op1 = encode_offset_flat(x.op1)
                    x.op2 = encode_offset_flat(x.op2)

            instructions += pyasm2.block(pyasm2.Label('%08x' % addr), instr)

        # remove any addresses that are from within the current section
        newlist = addresses[:]
        for i in xrange(len(addresses)):
            if addresses[i] >= pe.OPTIONAL_HEADER.ImageBase + \
                    section.VirtualAddress and addresses[i] < \
                    pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + \
                    len(section.get_data()):
                newlist[i] = None
        addresses = filter(lambda x: x is not None, newlist)

    # walk over each instruction, if it has references, we update them
    for instr in instructions.instructions:
        # we can skip labels
        if isinstance(instr, pyasm2.Label):
            continue

        # check for references to imports
        if isinstance(instr, pyasm2.RelativeJump):
            # not very good, but for now (instead of checking relocs) we check
            # if the index is in the iat tabel..
            if int(instr.lbl.index, 16) in iat_label:
                instr.lbl.index = iat_label[int(instr.lbl.index, 16)]
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
        # if there is memory left
        for left in xrange(section.Misc_VirtualSize - len(data)):
            program.append('.lcomm __lbl_%08x, 1, 32' % (
                pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + left))

    # now we define all xmm's etc we gathered
    program.append('.align 4')
    program += m32s
    program.append('.align 16')
    program += m128s

    # time to define 'main'
    program.append('.globl _main')

    OEP = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # append each instruction
    for instr in instructions.instructions:
        # if this is an label, we want a colon as postfix
        if isinstance(instr, pyasm2.Label):
            program.append(str(instr) + ':')

            # if OEP is at this address, we will also add the `_main' label
            if str(instr) == '__lbl_%08x' % OEP:
                program.append('_main:')

                # we have to initialize the stack register, so..
                # for now we assume esp gpr is stored as first gpr in xmm7
                program.append('movd xmm7, esp')
        else:
            # TODO: fix this terrible hack as well
            program.append(str(instr).replace('byte', 'byte ptr').replace(
                'word', 'word ptr').replace('retn', 'ret').replace(
                '__lbl_00400000', '0x400000').replace('oword ptr', ''))

    print '\n'.join(program)

def ssexy_linux(fname):
    pass

if __name__ == '__main__':
    sys.stderr.write('ssexy v0.1    (C) 2012 Jurriaan Bremer\n')
    if len(sys.argv) != 2:
        print 'Usage: %s <binary>' % sys.argv[0]
        exit(0)

    # simple.. but suffices for now ;x
    if sys.argv[1].find('.exe') > 0:
        ssexy_win32(sys.argv[1])
    else:
        ssexy_linux(sys.argv[1])
