import struct
from elftools.elf.elffile import ELFFile

def read_words(stream, n=1):
    return struct.unpack('I'*n, stream.read(4*n))


def get_list(elf, section_name):
    section = elf.get_section_by_name(section_name)
    section.stream.seek(section.header.sh_offset)
    num_items = section.header.sh_size / section.header.sh_addralign
    items = read_words(section.stream, num_items)
    assert items[0] == 0xffffffff and items[-1] == 0
    return items[1:-1]


def get_classlist(elf):
    return get_list(elf, '__DATA, __objc_classlist, regular, no_dead_strip')

#def get_nlclslist(elf):
#    return get_list(elf, '__DATA, __objc_nlclslist, regular, no_dead_strip')

#def get_catlist(elf):
#    return get_list(elf, '__DATA, __objc_catlist, regular, no_dead_strip')


def decompile(elf):
    #symbols = elf.get_section_by_name('.dynsym').iter_symbols()
    #symbols = { x.entry.st_value: x.name for x in symbols }
    #objc_data = elf.get_section_by_name('__DATA, __objc_data')
    #assert objc_data is not None

    for cls in get_classlist(elf):
        print cls



    #start = objc_data.header.sh_offset
    #end = start + objc_data.header.sh_size
    #for i in range(start, end, 20):
    #    print hex(i), symbols[i]


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        sys.stderr.write('usage: decompile.py </path/to/libsomething.so>\n')
    with open(sys.argv[1]) as lib:
        decompile(ELFFile(lib))
