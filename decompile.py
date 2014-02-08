import struct
from elftools.elf.elffile import ELFFile


classlist_section_name = '__DATA, __objc_classlist, regular, no_dead_strip'


offset_cache = {}

def lookup(stream, offset, cls=None):
    if offset not in offset_cache:
        if cls is None:
            raise KeyError, offset
        offset_cache[offset] = cls(stream, offset)
    return offset_cache[offset]


def read_words(stream, n=1):
    return struct.unpack('I'*n, stream.read(4*n))


def _get_list(elf, section_name, cls):
    section = elf.get_section_by_name(section_name)
    section.stream.seek(section.header.sh_offset)
    num_items = section.header.sh_size / section.header.sh_addralign
    items = read_words(section.stream, num_items)
    assert items[0] == 0xffffffff and items[-1] == 0
    return (lookup(section.stream, offset, cls) for offset in items[1:-1])


def get_classlist(elf):
    '''Pointers to class structs in __objc_data.'''
    return _get_list(elf, classlist_section_name, Class)


def String(stream, offset):
    stream.seek(offset)
    chars = []
    while True:
        ch = stream.read(1)
        if ch == '\0':
            return ''.join(chars)
        else:
            chars.append(ch)


class List(list):

    _default = []

    def __init__(self, stream, offset, cls):
        stream.seek(offset)
        entsize, count = read_words(stream, 2)
        for i in range(count):
            self.append(cls(stream, offset + 8 + i * entsize))


class Struct(object):

    _default = None

    def __init__(self, stream, offset, fields):
        self._stream = stream
        self._offset = offset
        stream.seek(offset)
        values = read_words(stream, len(fields))
        for pair, value in zip(fields, values):
            name, cls = pair
            if cls is not None:
                if value == 0:
                    value = getattr(self, '_default', None)
                else:
                    value = lookup(stream, value, cls)
            setattr(self, name, value)


class Class(Struct):

    def __init__(self, stream, offset):
        Struct.__init__(self, stream, offset, \
                [('isa', Class)
                ,('super', Class)
                ,('cache', None)
                ,('vtable', None)
                ,('ro', ClassRO)])

    def __getattr__(self, name):
        return getattr(self.ro, name)

    def __repr__(self):
        return self.ro.name


class ClassRO(Struct):

    def __init__(self, stream, offset):
        Struct.__init__(self, stream, offset, \
                [('flags', None)
                ,('instanceStart', None)
                ,('instanceSize', None)
                ,('ivarLayout', None)
                ,('name', String)
                ,('baseMethods', MethodList)
                ,('baseProtocols', None)
                ,('ivars', IVarList)
                ,('weakIvarLayout', None)
                ,('properties', None)])

    def __getattr__(self, name):
        for ivar in self.ivars:
            if ivar.name == name:
                return ivar
        for method in self.baseMethods:
            if method.cmd == name:
                return method
        raise AttributeError, name

class MethodList(List):
    def __init__(self, stream, offset):
        List.__init__(self, stream, offset, Method)


class Method(Struct):

    def __init__(self, stream, offset):
        Struct.__init__(self, stream, offset,
                [('cmd', String)
                ,('method_type', String)
                ,('imp', None)])

    def __repr__(self):
        return self.cmd

class IVarList(List):
    def __init__(self, stream, offset):
        List.__init__(self, stream, offset, IVar)


class IVar(Struct):
    def __init__(self, stream, offset):
        Struct.__init__(self, stream, offset,
                [('offset', None)
                ,('name', String)
                ,('type', String)
                ,('alignment', None)
                ,('size', None)])

    def __repr__(self):
        return self.name


def decompile(stream):
    elf = ELFFile(stream)
    #symbols = elf.get_section_by_name('.dynsym').iter_symbols()
    #symbols = { x.entry.st_value: x.name for x in symbols }
    #objc_data = elf.get_section_by_name('__DATA, __objc_data')
    #assert objc_data is not None

    classlist = get_classlist(elf)
    for cls in get_classlist(elf):
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
