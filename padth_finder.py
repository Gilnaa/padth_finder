#!/usr/bin/env python

import os
import sys
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_attr_value
from collections import OrderedDict


# Type States
STATE_INITIAL = 0
STATE_IN_PROCESS = 1
STATE_FINALIZED = 2


class Type(object):
    def __init__(self, die):
        self.source_object = die
        self.name = None
        self.byte_size = None
        self.state = STATE_INITIAL

    def finalize(self, types):
        if self.state == STATE_FINALIZED:
            return

        if self.state == STATE_IN_PROCESS:
            raise RuntimeError("Type cycle detected")

        self.state = STATE_IN_PROCESS
        self.do_finalize(types)
        self.state = STATE_FINALIZED

    def do_finalize(self, types):
        pass

    def has_padding(self):
        return False

    def get_location(self):
        node = self.source_object
        while node is not None and node.tag != 'DW_TAG_compile_unit':
            node = node.get_parent()

        if node is None:
            return None

        comp_dir = node.attributes['DW_AT_comp_dir'].value
        file_name = node.attributes['DW_AT_name'].value
        file_name = os.path.join(comp_dir, file_name)
        return file_name


class Primitive(Type):
    def __init__(self, die):
        super().__init__(die)

        self.name = die.attributes['DW_AT_name'].value.decode('utf-8')

        self.byte_size = die.attributes['DW_AT_byte_size'].value

    def __repr__(self):
        return self.name


class Struct(Type):
    def __init__(self, die):
        super().__init__(die)

        self.name = None
        if 'DW_AT_name' in die.attributes:
            self.name = die.attributes['DW_AT_name'].value.decode('utf-8')

        self.byte_size = die.attributes['DW_AT_byte_size'].value
        self.members = []
        for c in die.iter_children():
            if c.tag not in ['DW_TAG_member', 'DW_TAG_inheritance']:
                continue

            type_num = c.attributes['DW_AT_type'].value
            self.members.append(type_num)

    def do_finalize(self, types):
        new_members = []

        for member in self.members:
            types[member].finalize(types)
            new_members.append(types[member])

        self.members = new_members

    def has_padding(self):
        return self.byte_size != sum(map(lambda t: t.byte_size, self.members)) or \
            any(map(lambda dm: dm.has_padding(), self.members))

    def __repr__(self):
        if len(self.members) == 0:
            return self.name

        return self.name + '(%s)' % ', '.join(map(str, self.members))


class Array(Type):
    def __init__(self, die):
        super().__init__(die)

        self.item_type = die.attributes['DW_AT_type'].value

        self.dimensions = []
        for c in die.iter_children():
            dimension = c.attributes['DW_AT_upper_bound'].value + 1
            self.dimensions.append(dimension)

    def do_finalize(self, types):
        assert len(self.dimensions) > 0

        self.item_type = types[self.item_type]
        self.byte_size = self.item_type.byte_size
        for d in self.dimensions:
            self.byte_size *= d

    def has_padding(self):
        return self.item_type.has_padding()

    def __repr__(self):
        if self.state != STATE_FINALIZED:
            return "<abstract array type>"

        base_type = "<anonymous>"
        if self.item_type.name is not None:
            base_type = self.item_type.name

        for d in self.dimensions:
            base_type += '[%u]' % d

        return base_type


class Typedef(Type):
    def __init__(self, die):
        super().__init__(die)

        self.name = die.attributes['DW_AT_name'].value.decode('utf-8')
        self.alias = die.attributes['DW_AT_type'].value

    def do_finalize(self, types):
        self.alias = types[self.alias]
        self.byte_size = self.alias.byte_size

    def has_padding(self):
        return self.alias.has_padding()

    def __repr__(self):
        return self.name


def main():
    with open(sys.argv[1], 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("Object file has no dwarf info!")
            sys.exit(1)

        types = {}

        global_offset = elf.get_dwarf_info().debug_info_sec.global_offset

        for cu in elf.get_dwarf_info().iter_CUs():
            cu_name = cu.get_top_DIE().attributes['DW_AT_name'].value.decode('utf-8')
            print('\x1b[32m\x1b[1mProcessing %s\x1b[0m' % cu_name)

            # First, map top level types
            dies = list(cu.iter_DIEs())

            i = 0
            while i < len(dies):
                offset = dies[i].offset
                current = dies[i]
                i += 1

                common_types = {
                    'DW_TAG_structure_type': Struct,
                    'DW_TAG_class_type': Struct,
                    'DW_TAG_base_type': Primitive,
                    'DW_TAG_typedef': Typedef,
                    'DW_TAG_array_type': Array,
                }

                if current.tag in common_types:
                    assert offset not in types
                    types[offset] = common_types[current.tag](current)
                else:
                    pass  # print("Skipping processing of '%s'" % current.tag)

            for t in types.values():
                t.finalize(types)

            header = '%-4s |\t%-100s |\t%s' % ('#', 'type', 'size')
            print(header)
            print('-' * len(header.expandtabs()))
            for o, t in types.items():
                color = '\x1b[31m\x1b[31m' if t.has_padding() else ''
                print('{:04x} |\t{color}{:100}\x1b[0m |\t{}'.format(o, repr(t), t.byte_size, color=color))
            print('-' * len(header.expandtabs()))
            print()
            for o, t in types.items():
                if t.has_padding():
                    print("Found padded type '%s' at %s:%u" % (t, cu_name, t.source_object.attributes['DW_AT_decl_line'].value))


if __name__ == '__main__':
    main()
