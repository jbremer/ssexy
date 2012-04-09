import sys, struct
from ctypes import *

class Address(c_uint):
    def __init__(self, offset):
        self.value = offset

    def offset(self, base):
        self.value += base
        return self.value

    def __int__(self):
        return self.value

    def __str__(self):
        return struct.pack('L', self.value)

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic', c_ushort),
        ('e_cblp', c_ushort),
        ('e_cp', c_ushort),
        ('e_crlc', c_ushort),
        ('e_cparhdr', c_ushort),
        ('e_minalloc', c_ushort),
        ('e_maxalloc', c_ushort),
        ('e_ss', c_ushort),
        ('e_sp', c_ushort),
        ('e_csum', c_ushort),
        ('e_ip', c_ushort),
        ('e_cs', c_ushort),
        ('e_lfarlc', c_ushort),
        ('e_ovno', c_ushort),
        ('e_res1', c_ushort * 4),
        ('e_oemid', c_ushort),
        ('e_oeminfo', c_ushort),
        ('e_res2', c_ushort * 10),
        ('e_lfanew', c_long)
    ]

IMAGE_FILE_MACHINE_I386 = 0x014c

class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Machine', c_ushort),
        ('NumberOfSections', c_ushort),
        ('TimeDateStamp', c_uint),
        ('PointerToSymbolTable', c_uint),
        ('NumberOfSymbols', c_uint),
        ('SizeOfOptionalHeader', c_ushort),
        ('Characteristics', c_ushort)
    ]

class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress', c_uint),
        ('Size', c_uint)
    ]

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_DIRECTORY_ENTRY_EXPORT     = 0
IMAGE_DIRECTORY_ENTRY_IMPORT     = 1
IMAGE_DIRECTORY_ENTRY_BASERELOC  = 5
IMAGE_DIRECTORY_ENTRY_TLS        = 9

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [
        ('Magic', c_ushort),
        ('MajorLinkerVersion', c_ubyte),
        ('MinorLinkerVersion', c_ubyte),
        ('SizeOfCode', c_uint),
        ('SizeOfInitializedData', c_uint),
        ('SizeOfUninitializedData', c_uint),
        ('AddressOfEntryPoint', c_uint),
        ('BaseOfCode', c_uint),
        ('BaseOfData', c_uint),
        ('ImageBase', c_uint),
        ('SectionAlignment', c_uint),
        ('FileAlignment', c_uint),
        ('MajorOperatingSystemVersion', c_short),
        ('MinorOperatingSystemVersion', c_short),
        ('MajorImageVersion', c_short),
        ('MinorImageVersion', c_short),
        ('MajorSubsystemVersion', c_short),
        ('MinorSubsystemVersion', c_short),
        ('Win32VersionValue', c_uint),
        ('SizeOfImage', c_uint),
        ('SizeOfHeaders', c_uint),
        ('CheckSum', c_uint),
        ('Subsystem', c_short),
        ('DllCharacteristics', c_short),
        ('SizeOfStackReserve', c_uint),
        ('SizeOfStackCommit', c_uint),
        ('SizeOfHeapReserve', c_uint),
        ('SizeOfHeapCommit', c_uint),
        ('LoaderFlags', c_uint),
        ('NumberOfRvaAndSizes', c_uint),
        ('DataDirectory',
            IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]

class IMAGE_NT_HEADERS(Structure):
    _fields_ = [
        ('Signature', c_uint),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER)
    ]

IMAGE_SIZEOF_SHORT_NAME = 8

class IMAGE_SECTION_HEADER_Misc(Union):
    _fields_ = [
        ('PhysicalAddress', c_uint),
        ('VirtualSize', c_uint)
    ]

class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ('Name', c_char * 8),
        ('Misc', IMAGE_SECTION_HEADER_Misc),
        ('VirtualAddress', c_uint),
        ('SizeOfRawData', c_uint),
        ('PointerToRawData', c_uint),
        ('PointerToRelocations', c_uint),
        ('PointerToLinenumbers', c_uint),
        ('NumberOfRelocations', c_short),
        ('NumberOfLinenumbers', c_short),
        ('Characteristics', c_uint)
    ]

class IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [
        ('Characteristics', c_uint),
        ('TimeDateStamp', c_uint),
        ('MajorVersion', c_short),
        ('MinorVersion', c_short),
        ('Name', c_uint),
        ('Base', c_uint),
        ('NumberOfFunctions', c_uint),
        ('NumberOfNames', c_uint),
        ('AddressOfFunctions', c_uint),
        ('AddressOfNames', c_uint),
        ('AddressOfNameOrdinals', c_uint)
    ]

class IMAGE_IMPORT_DESCRIPTOR_Union(Union):
    _fields_ = [
        ('Characteristics', c_uint),
        ('OriginalFirstThunk', Address)
    ]

class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _anonymous_ = ('DummyUnionName', )
    _fields_ = [
        ('DummyUnionName', IMAGE_IMPORT_DESCRIPTOR_Union),
        ('TimeDateStamp', c_uint),
        ('ForwarderChain', Address),
        ('Name', Address),
        ('FirstThunk', Address)
    ]

IMAGE_ORDINAL_FLAG32 = 0x80000000

class IMAGE_THUNK_DATA32(Union):
    _fields_ = [
        ('ForwarderString', c_uint),
        ('Function', c_uint),
        ('Ordinal', c_uint),
        ('AddressOfData', Address)
    ]

class IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [
        ('Hint', c_ushort),
    ]

class ImportedFunction:
    def __init__(self, library, function=None):
        self.library = library
        self.function = function

class IMAGE_BASE_RELOCATION(Structure):
    _fields_ = [
        ('VirtualAddress', c_uint),
        ('SizeOfBlock', c_uint)
    ]

class IMAGE_FIXUP_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ('Offset', c_uint, 12),
        ('Type', c_uint, 4)
    ]

class IMAGE_TLS_DIRECTORY32(Structure):
    _fields_ = [
        ('StartAddressOfRawData', c_uint),
        ('EndAddressOfRawData', c_uint),
        ('AddressOfIndex', c_uint),
        ('AddressOfCallBacks', c_uint),
        ('SizeOfZeroFill', c_uint),
        ('Characteristics', c_uint)
    ]

def ctype_encode(obj):
    ret = []
    if not hasattr(obj, '_fields_'): return obj
    for name, field in obj._fields_:
        value = getattr(obj, name)
        if isinstance(value, Structure):
            ret.append({name: ctype_encode(value)})
        if hasattr(value, '_length_'):
            ret.append({name: [ctype_encode(x) for x in value]})
        else:
            ret.append({name: value})
    return ret

def roundup(num, align):
    return (num + align - 1) / align * align

class Section:
    """Section helps creating complex datastructures with dangling pointers.

    Section has a few methods:
    offset() -- Apply an offset to all pointers from this Section.
    pointer() -- When this Section's offset is updated, also update this
        Address.
    __len__() -- length of the section, including all it's children
    __str__() -- returns the section, represented as a string
    __iadd__() -- add a child (+= is overloaded), childs can be one of the
        following types: Address, Structure, array of Structure, Union,
        Section, ctype, str

    """
    def __init__(self):
        """Initialize a new Section object."""
        self._child = []
        self._pointer = []

    def _offset_apply(self, offset):
        # process all our pointers
        for obj, field in self._pointer:
            if isinstance(obj, Address):
                obj.offset(offset)
            elif isinstance(obj, Section):
                obj._offset_apply(offset)
            else:
                # the attribute should support the offset() function call
                # thereby we demand it's an Address() object.
                getattr(obj, field).offset(offset)

        # process pointers in children (we don't need this, if I'm not mistaken)
        #for child in self._child:
        #    if isinstance(child, Section):
        #        child._offset_apply(offset)

    def offset(self, offset):
        """Apply an offset to all pointers from this Section."""
        self._offset_apply(offset)
        return self

    def pointer(self, addr, field=None):
        """When this Section's offset is updated, also update this Address."""
        self._pointer.append([addr, field])
        return addr

    def __iadd__(self, other):
        """Add a child."""
        self._child.append(other)
        return self

    def _len(self, obj, field=None):
        if hasattr(obj, '_length_'):
            return obj._length_ * sizeof(obj._type_)
        if isinstance(obj, Address):
            return sizeof(obj)
        if isinstance(obj, (Section, str)):
            return len(obj)
        if hasattr(field, '_type_'):
            return len(struct.pack(field._type_, obj))
        if isinstance(obj, Structure):
            return sum([self._len(getattr(obj, name), field) for name, field in
                obj._fields_])
        if isinstance(obj, Union):
            return max([self._len(getattr(obj, name), field) for name, field in
                obj._fields_])
        raise Exception('aup?')

    def __len__(self, field=None):
        """Calculate the length of this section."""
        return sum([self._len(child) for child in self._child])

    def _str(self, obj, field=None):
        if isinstance(obj, Address):
            return struct.pack('L', int(obj))

        if isinstance(obj, Section):
            return str(obj)

        if hasattr(obj, '_length_'):
            ret = ''
            for x in obj:
                tmp = self._str(x, obj._type_)
                ret += tmp
            # append padding
            return ret + '\x00' * (obj._length_ - len(ret))

        if isinstance(obj, str):
            #print 'instance', type(obj), field
            return obj

        if hasattr(field, '_type_'):
            ret = struct.pack(field._type_, obj)
            return ret

        if isinstance(obj, Structure):
            ret = ''
            for name, field in obj._fields_:
                tmp = self._str(getattr(obj, name), field)
                ret += tmp
            return ret

        if isinstance(obj, Union):
            size = sizeof(obj)
            buf = create_string_buffer(size)
            memmove(byref(buf), byref(obj), size)
            return buf[:size]

    def __str__(self):
        """Returns a string representing this section."""
        return ''.join([self._str(child) for child in self._child])

class Penis:
    def read(self, fname=None, raw=None):
        # get the entire contents of the pe file
        self.raw = raw if raw else file(fname, 'rb').read()

    # relative virtual address to raw offset
    def rva2ro(self, rva):
        for section in self.ImageSectionHeaders:
            if rva >= section.VirtualAddress and \
                    rva < section.VirtualAddress + section.SizeOfRawData:
                return rva - section.VirtualAddress + section.PointerToRawData
        raise Exception('Invalid Relative Virtual Address', hex(rva))

    # virtual address to raw offset
    def va2ro(self, rva):
        return self.rva2ro(rva - self.ImageNtHeaders.OptionalHeader.ImageBase)

    # parse the Import Address Table
    def parseImportAddressTable(self, section):
        self.ImportAddressTable = []
        if section.VirtualAddress and section.Size:
            # find the address
            offsetImageImportDescriptor = self.rva2ro(section.VirtualAddress)
            while True:
                # extract the Image Import Descriptor
                ImageImportDescriptor = \
                    IMAGE_IMPORT_DESCRIPTOR.from_buffer_copy(self.raw,
                        offsetImageImportDescriptor)
                offsetImageImportDescriptor += sizeof(IMAGE_IMPORT_DESCRIPTOR)

                # last Image Import Descriptor ends with a zero-structure
                if ImageImportDescriptor.Characteristics == 0: break

                # resolve library name
                library = self.rva2ro(ImageImportDescriptor.Name)
                library = self.raw[library:self.raw.find('\x00', library)]

                # resolve thunkOut and thunkIn
                thunkOut = self.rva2ro(ImageImportDescriptor.FirstThunk)
                thunkIn = thunkOut if \
                    ImageImportDescriptor.OriginalFirstThunk == 0 else \
                    self.rva2ro(ImageImportDescriptor.OriginalFirstThunk)

                # check if all lookups were successful
                if not library or not thunkOut or not thunkIn: break

                # thunk address of each Imported API
                thunkAddress = ImageImportDescriptor.FirstThunk
                while True:
                    entry = ImportedFunction(library)
                    thunk = IMAGE_THUNK_DATA32.from_buffer_copy(self.raw,
                        thunkIn)
                    if thunk.Function == 0: break

                    # Import by Ordinal rather than Function Name
                    if thunk.Ordinal & IMAGE_ORDINAL_FLAG32:
                        entry.ordinal = thunk.Ordinal & 0xffff
                        entry.function = None
                    # Import by Function Name
                    else:
                        nameOffset = self.rva2ro(thunk.AddressOfData)
                        importByName = IMAGE_IMPORT_BY_NAME.from_buffer_copy(
                            self.raw, nameOffset)
                        entry.ordinal = importByName.Hint
                        entry.function = create_string_buffer(
                            self.raw[nameOffset+2:]).value
                    entry.thunk = thunkAddress

                    # add this entry
                    self.ImportAddressTable.append(entry)

                    thunkIn += sizeof(IMAGE_THUNK_DATA32)
                    thunkAddress += sizeof(IMAGE_THUNK_DATA32)

    # parse the Relocation Data
    def parseRelocationData(self, section):
        self.RelocationTable = []
        if section.VirtualAddress and section.Size:
            offsetImageBaseRelocation = self.rva2ro(section.VirtualAddress)
            while True:
                # extract Image Base Relocation object
                ImageBaseRelocation = IMAGE_BASE_RELOCATION.from_buffer_copy(
                    self.raw, offsetImageBaseRelocation)
                if ImageBaseRelocation.SizeOfBlock == 0: break

                offsetImageFixupEntry = offsetImageBaseRelocation + \
                    sizeof(IMAGE_BASE_RELOCATION)
                countImageFixupEntry = (ImageBaseRelocation.SizeOfBlock -
                    sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_FIXUP_ENTRY)

                # extract all Image Fixup Entries
                entries = (IMAGE_FIXUP_ENTRY * countImageFixupEntry). \
                    from_buffer_copy(self.raw, offsetImageFixupEntry)

                # add each entry
                for entry in entries:
                    if entry.Type != 3:
                        raise Exception('Unknown Relocation Type',
                            str(entry.Type))
                    self.RelocationTable.append(
                        ImageBaseRelocation.VirtualAddress + entry.Offset)

                # next block
                offsetImageBaseRelocation += ImageBaseRelocation.SizeOfBlock

            # sort the list of relocations
            self.RelocationTable.sort()

    # parse Thread Local Storage
    def parseThreadLocalStorage(self, section):
        self.ThreadLocalStorageCallbacks = []
        if section.VirtualAddress and section.Size:
            offsetImageTlsDirectory = self.rva2ro(section.VirtualAddress)
            ImageTlsDirectory = IMAGE_TLS_DIRECTORY32.from_buffer_copy(
                self.raw, offsetImageTlsDirectory)
            offsetCallback = self.va2ro(ImageTlsDirectory.AddressOfCallBacks)
            while True:
                callback = c_uint.from_buffer_copy(self.raw,
                    offsetCallback).value
                if callback == 0: break

                self.ThreadLocalStorageCallbacks.append(callback)
                offsetCallback += sizeof(c_uint)

    def parse(self):
        # parse Image Dos Header
        self.ImageDosHeader = IMAGE_DOS_HEADER.from_buffer_copy(self.raw)
        print ctype_encode(self.ImageDosHeader)

        # parse Image Nt Headers
        self.ImageNtHeaders = IMAGE_NT_HEADERS.from_buffer_copy(self.raw,
            self.ImageDosHeader.e_lfanew)
        print ctype_encode(self.ImageNtHeaders)

        # parse the Image Section Headers
        self.ImageSectionHeaders = []
        for index in xrange(self.ImageNtHeaders.FileHeader.NumberOfSections):
            # extract the Image Section Header
            offset = self.ImageDosHeader.e_lfanew + sizeof(c_uint) + \
                sizeof(IMAGE_FILE_HEADER) + \
                self.ImageNtHeaders.FileHeader.SizeOfOptionalHeader
            ImageSectionHeader = IMAGE_SECTION_HEADER.from_buffer_copy(self.raw,
                offset + index * sizeof(IMAGE_SECTION_HEADER))

            # extract the Data from the Header
            ImageSectionHeader.raw = self.raw[
                ImageSectionHeader.PointerToRawData :
                ImageSectionHeader.PointerToRawData +
                ImageSectionHeader.SizeOfRawData]

            # add the header
            self.ImageSectionHeaders.append(ImageSectionHeader)
            print ctype_encode(ImageSectionHeader)

        # parse Import Address Table
        ImportAddressTableSection = \
            self.ImageNtHeaders.OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_IMPORT]
        self.parseImportAddressTable(ImportAddressTableSection)

        # parse Relocation Data
        RelocationDataSection = \
            self.ImageNtHeaders.OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_BASERELOC]
        self.parseRelocationData(RelocationDataSection)

        # parse Thread Local Storage
        ThreadLocalStorageSection = \
            self.ImageNtHeaders.OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_TLS]
        self.parseThreadLocalStorage(ThreadLocalStorageSection)

    # returns a section object
    def createImportAddressTable(self):
        iat_section = Section()
        library_names_section = Section()
        thunks_section = Section()
        function_names_section = Section()

        # each library name, TODO lowercase?
        for library in sorted(set([entry.library for entry in
                self.ImportAddressTable])):
            ImageImportDescriptor = IMAGE_IMPORT_DESCRIPTOR()
            ImageImportDescriptor.OriginalFirstThunk = 0
            ImageImportDescriptor.FirstThunk = Address(len(thunks_section))
            thunks_section.pointer(ImageImportDescriptor, field='FirstThunk')
            ImageImportDescriptor.TimeDateStamp = 0
            ImageImportDescriptor.ForwarderChain = -1
            ImageImportDescriptor.Name = len(library_names_section)
            library_names_section.pointer(ImageImportDescriptor, field='Name')
            library_names_section += library + '\x00'
            iat_section += ImageImportDescriptor

            for entry in filter(lambda x: x.library == library,
                    self.ImportAddressTable):
                ImageThunkData = IMAGE_THUNK_DATA32()
                ImageThunkData.AddressOfData = \
                    Address(len(function_names_section))
                function_names_section.pointer(ImageThunkData,
                    field='AddressOfData')
                thunks_section += ImageThunkData
                ImageImportByName = IMAGE_IMPORT_BY_NAME()
                ImageImportByName.Hint = 0
                function_names_section += ImageImportByName
                function_names_section += entry.function + '\x00'

            # add an empty Thunks entry
            thunks_section += IMAGE_THUNK_DATA32()

        # append an empty Image Import Descriptor
        iat_section += IMAGE_IMPORT_DESCRIPTOR()

        # add the library names
        library_names_section.offset(len(iat_section))
        iat_section += iat_section.pointer(library_names_section)

        # add the thunk data
        thunks_section.offset(len(iat_section))
        iat_section += iat_section.pointer(thunks_section)

        # add the function names
        function_names_section.offset(len(iat_section))
        iat_section += iat_section.pointer(function_names_section)

        # return the section
        return iat_section

    def createTreadLocalStorage(self):
        return Section()

    def createResourceData(self):
        return Section()

    def create(self, fname=True):
        # this buffer will contain the entire pe file
        buf = Section()

        # copy the ImageDosHeader
        buf += self.ImageDosHeader

        # copy the part between ImageNtHeaders and ImageDosHeader
        buf += self.raw[sizeof(self.ImageDosHeader):
                self.ImageDosHeader.e_lfanew]

        # copy the ImageNtHeaders
        buf += self.ImageNtHeaders

        # section headers
        section_headers = {}

        # create code section
        code_section = Section()
        section_headers['.text'] = code_section

        # create Import Address Table
        section_headers['.idata'] = self.createImportAddressTable()

        # create Resource Section
        section_headers['.rsrc'] = self.createResourceData()

        # create Thread Local Storage
        section_headers['.tls'] = self.createThreadLocalStorage()

        # section count
        self.ImageNtHeaders.FileHeader.NumberOfSections = len(section_headers)

        # calculate size of all sections together
        # aligned nicely to the Section Alignment
        size = sum([roundup(len(section),
            self.ImageNtHeaders.OptionalHeader.SectionAlignment)
            for section in section_headers])

        # copy the ImageSectionHeaders
        offset = self.ImageDosHeader.e_lfanew + sizeof(c_uint) + \
            sizeof(IMAGE_FILE_HEADER) + \
            self.ImageNtHeaders.FileHeader.SizeOfOptionalHeader

        # copy the headers of each section
        for name, section in section_headers.values():
            SectionHeader = IMAGE_SECTION_HEADER()
            SectionHeader.Name = name
            #SectionHeader.
            buf += section

        offset = roundup(len(buf),
                self.ImageNtHeaders.OptionalHeader.FileAlignment)
        buf += '\x00' * (offset - len(buf))

        # copy all sections
        relative_virtual_address = roundup(len(buf),
            self.ImageNtHeaders.OptionalHeader.SectionAlignment)
        for section in self.ImageSectionHeaders:
            section.PointerToRawData = len(buf)
            section.SizeOfRawData = len(section.raw)
            section.VirtualAddress = relative_virtual_address
            section.Misc.VirtualSize = roundup(section.SizeOfRawData,
                self.ImageNtHeaders.OptionalHeader.SectionAlignment)
            relative_virtual_address += section.Misc.VirtualSize
            buf += section.raw + '\x00' * (roundup(section.SizeOfRawData,
                self.ImageNtHeaders.OptionalHeader.FileAlignment) -
                section.SizeOfRawData)

        # write the contents to a file
        buf = str(buf)
        if fname: file(fname, 'wb').write(buf)
        return buf

if __name__ == '__main__':
    # set a default parameter..
    sys.argv = (sys.argv[0], 'yasm.exe')
    if len(sys.argv) == 1:
        print 'Usage: %s <filename>' % sys.argv[0]
        exit(0)

    # test basic offset logic from `Section'
    s = Section()
    s += Address(0)
    x = Section()
    x += 'w00t'
    x += Address(0x44444444)
    s += x
    assert str(s) == '\x00\x00\x00\x00w00t\x44\x44\x44\x44'

    # test `_length_' logic in `Section'
    s = Section()
    s += (c_uint * 4).from_buffer_copy('AAAABBBBCCCCDDDD')
    assert len(s) == 16

    # test `Structure'
    s = Section()
    x = IMAGE_IMPORT_DESCRIPTOR.from_buffer_copy('A' * 32)
    x.FirstThunk = Address(0x66666666)
    s += x
    assert str(s) == 'A' * 16 + 'f' * 4

    # test nested `Section' objects
    s = Section()
    s += 'A' * 8
    x = Section()
    x += 'B' * 4
    s += Address(0xdeadf00d)        # this address _will not_ be updated
    s += s.pointer(Address(len(x))) # this address _will_ be updated
    s += x
    s.offset(0x1337b00b)
    assert str(s) == 'A' * 8 + '\x0d\xf0\xad\xde\x0f\xb0\x37\x13' + 'B' * 4

    # test IAT
    s = Penis()
    s.ImportAddressTable = [
            ImportedFunction('aup', 'lol'), ImportedFunction('aup2', 'omg'),
            ImportedFunction('aup', 'rofl'), ImportedFunction('aup', 'w00t')
    ]
    print str(s.createImportAddressTable().offset(0x1000))
    exit(0)

    pe = Penis()
    pe.read(sys.argv[1])
    pe.parse()

    for dir in pe.ImageNtHeaders.OptionalHeader.DataDirectory:
        print 'datadir 0x%08x 0x%08x' % (dir.VirtualAddress, dir.Size)

    for section in pe.ImageSectionHeaders:
        print 'section %-8s 0x%08x 0x%08x 0x%08x 0x%08x' % (section.Name,
            section.VirtualAddress, section.Misc.VirtualSize,
            section.PointerToRawData, section.SizeOfRawData)

    for entry in pe.ImportAddressTable:
        print 'iat %s %d %s 0x%08x' % (entry.library, entry.ordinal,
            entry.function, entry.thunk)

    for x in pe.RelocationTable:
        print 'reloc 0x%08x' % x

    for cb in pe.ThreadLocalStorageCallbacks:
        print 'tls 0x%08x' % cb

    pe.create(sys.argv[1].replace('.exe', '.out.exe'))
