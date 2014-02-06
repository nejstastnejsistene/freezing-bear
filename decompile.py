import struct
from elftools.elf.elffile import ELFFile

def read_words(stream, n=1):
    return struct.unpack('I'*n, stream.read(4*n))

def read_string(stream, offset):
    stream.seek(offset)
    chars = []
    while True:
        ch = stream.read(1)
        if ch == '\0':
            return ''.join(chars)
        else:
            chars.append(ch)


def get_list(elf, section_name):
    section = elf.get_section_by_name(section_name)
    section.stream.seek(section.header.sh_offset)
    num_items = section.header.sh_size / section.header.sh_addralign
    items = read_words(section.stream, num_items)
    assert items[0] == 0xffffffff and items[-1] == 0
    return items[1:-1]


def get_classlist(elf):
    '''Pointers to class structs in __objc_data.'''
    return get_list(elf, '__DATA, __objc_classlist, regular, no_dead_strip')

def get_classrefs(elf):
    '''References pointing to an entry in the classlist.'''
    return get_list(elf, '__DATA, __objc_classrefs, regular, no_dead_strip')

#def get_nlclslist(elf):
#    return get_list(elf, '__DATA, __objc_nlclslist, regular, no_dead_strip')

#def get_catlist(elf):
#    return get_list(elf, '__DATA, __objc_catlist, regular, no_dead_strip')

#def get_protolist(elf):
#    return get_list(, '__DATA, __objc_protolist, coalesced, no_dead_strip')

#def get_nlcatlist(elf):
#    return get_list(elf, '__DATA, __objc_nlcatlist, regular, no_dead_strip')


def from_ptr(stream, offset, cls, default=None):
    return default if offset == 0 else cls(stream, offset)


class ObjCClass(object):
    def __init__(self, stream, offset):
        stream.seek(offset)
        fields = read_words(stream, 5)
        self.isa = from_ptr(stream, fields[0], ObjCClass)
        self.super = from_ptr(stream, fields[1], ObjCClass)
        self.cache = fields[2]
        self.vtable = fields[3]
        self.ro = from_ptr(stream, fields[4], ObjCClassRO)

    def __getattr__(self, name):
        return getattr(self.ro, name)

    def __repr__(self):
        return self.ro.name


class ObjCClassRO(object):
    def __init__(self, stream, offset):
        stream.seek(offset)
        fields = read_words(stream, 10)
        self.flags = fields[0]
        self.instanceStart = fields[1]
        self.instanceSize = fields[2]
        self.ivarLayout = fields[3]
        self.name = read_string(stream, fields[4])
        self.baseMethods = from_ptr(stream, fields[5], ObjCMethodList, [])
        self.baseProtocols = fields[6]
        self.ivars = from_ptr(stream, fields[7], ObjCIVarList, [])
        self.weakIvarLayout = fields[8]
        self.properties = fields[9]
    def __getattr__(self, name):
        for ivar in self.ivars:
            if ivar.name == name:
                return ivar
        for method in self.baseMethods:
            if method.cmd == name:
                return method
        raise AttributeError, name

class ObjCMethodList(list):
    def __init__(self, stream, offset):
        stream.seek(offset)
        entsize, method_count = read_words(stream, 2)
        for i in range(method_count):
            self.append(ObjCMethod(stream, offset + 8 + i * entsize))

class ObjCMethod(object):
    def __init__(self, stream, offset):
        stream.seek(offset)
        fields = read_words(stream, 3)
        self.cmd = read_string(stream, fields[0])
        self.method_type = read_string(stream, fields[1])
        self.imp = fields[2]
    def __repr__(self):
        return self.cmd

class ObjCIVarList(list):
    def __init__(self, stream, offset):
        stream.seek(offset)
        entsize, ivar_count = read_words(stream, 2)
        for i in range(ivar_count):
            self.append(ObjCIVar(stream, offset+8+i*entsize))

class ObjCIVar(object):
    def __init__(self, stream, offset):
        stream.seek(offset)
        fields = read_words(stream, 5)
        self.offset = fields[0]
        self.name = read_string(stream, fields[1])
        self.type = read_string(stream, fields[2])
        self.alignment = fields[3]
        self.size = fields[4]
    def __repr__(self):
        return self.name

def decompile(stream):
    elf = ELFFile(stream)
    #symbols = elf.get_section_by_name('.dynsym').iter_symbols()
    #symbols = { x.entry.st_value: x.name for x in symbols }
    #objc_data = elf.get_section_by_name('__DATA, __objc_data')
    #assert objc_data is not None

    classlist = get_classlist(elf)
    for off in classlist:
        cls = ObjCClass(stream, off)
        if 'AddNew' in cls.name:
            print cls.super.getRandomDotClass.method_type



    #start = objc_data.header.sh_offset
    #end = start + objc_data.header.sh_size
    #for i in range(start, end, 20):
    #    print hex(i), symbols[i]


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        sys.stderr.write('usage: decompile.py </path/to/libsomething.so>\n')
    with open(sys.argv[1]) as lib:
        decompile(lib)
