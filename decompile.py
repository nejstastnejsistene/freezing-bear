import struct
from collections import defaultdict
from elftools.elf.elffile import ELFFile


classlist_section_name = '__DATA, __objc_classlist, regular, no_dead_strip'

class FreezingBear(object):

    def __init__(self, stream):
        self.stream = stream
        self.elf = ELFFile(stream)
        self.by_offset = {}
        self.by_class = defaultdict(lambda: [])
        self.get_classlist()

    def lookup(self, offset, cls=None):
        if offset not in self.by_offset:
            if cls is None:
                raise KeyError, offset
            obj = cls(self, offset)
            self.by_offset[offset] = obj
            self.by_class[cls].append(obj)
        return self.by_offset[offset]

    def read_words(self, n=1):
        return struct.unpack('I'*n, self.stream.read(4*n))

    def get_classlist(self):
        section = self.elf.get_section_by_name(classlist_section_name)
        return self.lookup(section.header.sh_offset, ClassList)


class PointerList(list):
    
    def __init__(self, bear, offset, cls):
        bear.stream.seek(offset)
        ptr = bear.read_words()[0]
        assert ptr == 0xffffffff
        ptr = bear.read_words()[0]
        while ptr != 0:
            self.append(bear.lookup(ptr, cls))
            offset += 4
            bear.stream.seek(offset)
            ptr = bear.read_words()[0]


class ClassList(PointerList):
    def __init__(self, bear, offset):
        PointerList.__init__(self, bear, offset, Class)


def String(bear, offset):
    bear.stream.seek(offset)
    chars = []
    while True:
        ch = bear.stream.read(1)
        if ch == '\0':
            return ''.join(chars)
        else:
            chars.append(ch)


class PropertyList(list):

    _default = []

    def __init__(self, bear, offset, cls):
        bear.stream.seek(offset)
        entsize, count = bear.read_words(2)
        for i in range(count):
            self.append(bear.lookup(offset + 8 + i * entsize, cls))


class Struct(object):

    _default = None

    def __init__(self, bear, offset, fields):
        bear.stream.seek(offset)
        values = bear.read_words(len(fields))
        for pair, value in zip(fields, values):
            name, cls = pair
            if cls is not None:
                if value == 0:
                    value = getattr(self, '_default', None)
                else:
                    value = bear.lookup(value, cls)
            setattr(self, name, value)


class Class(Struct):

    def __init__(self, bear, offset):
        Struct.__init__(self, bear, offset, \
                [('isa', Class)
                ,('super', Class)
                ,('cache', None)
                ,('vtable', None)
                ,('ro', ClassRO)])

    def is_metaclass(self):
        return self.isa is None

    def __getattr__(self, name):
        return getattr(self.ro, name)

    def __repr__(self):
        return self.ro.name


class ClassRO(Struct):

    def __init__(self, bear, offset):
        Struct.__init__(self, bear, offset, \
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

class MethodList(PropertyList):
    def __init__(self, bear, offset):
        PropertyList.__init__(self, bear, offset, Method)


class Method(Struct):

    def __init__(self, bear, offset):
        Struct.__init__(self, bear, offset,
                [('cmd', String)
                ,('method_type', String)
                ,('imp', None)])

    def __repr__(self):
        return self.cmd

class IVarList(PropertyList):
    def __init__(self, bear, offset):
        PropertyList.__init__(self, bear, offset, IVar)


class IVar(Struct):
    def __init__(self, bear, offset):
        Struct.__init__(self, bear, offset,
                [('offset', None)
                ,('name', String)
                ,('type', String)
                ,('alignment', None)
                ,('size', None)])

    def __repr__(self):
        return self.name


def decompile(bear):
    criteria = lambda x: 'AddNew' in x.name and not x.is_metaclass()
    cls, = filter(criteria, bear.by_class[Class])
    print hex(cls.super.getRandomDotClass.imp)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        sys.stderr.write('usage: decompile.py </path/to/libsomething.so>\n')
    with open(sys.argv[1]) as lib:
        decompile(FreezingBear(lib))
