import claripy
from collections import ChainMap
import logging

from .. import sim_options as options
from .memory_object import SimMemoryObject

l = logging.getLogger(name=__name__)

#pylint:disable=unidiomatic-typecheck

class SimFlatMemory:
    """
    Represents flat memory.
    """
    def __init__(self, memory_backer=None, permissions_backer=None, memory_array=None, initialized=None, name_mapping=None, hash_mapping=None, check_permissions=False):
        self._cowed = set()
        self._memory_backer = { } if memory_backer is None else memory_backer
        self._permissions_backer = permissions_backer # saved for copying
        self._executable_pages = False if permissions_backer is None else permissions_backer[0]
        self._permission_map = { } if permissions_backer is None else permissions_backer[1]
        self._initialized = set() if initialized is None else initialized
        self.state = None
        self._preapproved_stack = range(0)
        self._check_perms = check_permissions

        # reverse mapping
        self._name_mapping = ChainMap() if name_mapping is None else name_mapping
        self._hash_mapping = ChainMap() if hash_mapping is None else hash_mapping
        self._updated_mappings = set()

        self.memory_array = claripy.ArrayV(64, claripy.BVV(0, 64)) if memory_array is None else memory_array
        self.addrs = set()

    def __getstate__(self):
        return {
            '_memory_backer': self._memory_backer,
            '_permissions_backer': self._permissions_backer,
            '_executable_pages': self._executable_pages,
            '_permission_map': self._permission_map,
            '_pages': self._pages,
            '_initialized': self._initialized,
            '_page_size': self._page_size,
            'state': None,
            '_name_mapping': self._name_mapping,
            '_hash_mapping': self._hash_mapping,
            '_symbolic_addrs': self._symbolic_addrs,
            '_preapproved_stack': self._preapproved_stack,
            '_check_perms': self._check_perms
        }

    def __setstate__(self, s):
        self._cowed = set()
        self.__dict__.update(s)

    def branch(self):
        new_name_mapping = self._name_mapping.new_child() if options.REVERSE_MEMORY_NAME_MAP in self.state.options else self._name_mapping
        new_hash_mapping = self._hash_mapping.new_child() if options.REVERSE_MEMORY_HASH_MAP in self.state.options else self._hash_mapping

        self._cowed = set()
        m = SimFlatMemory(memory_backer=self._memory_backer,
                          permissions_backer=self._permissions_backer,
                           initialized=set(self._initialized),
                           name_mapping=new_name_mapping,
                           hash_mapping=new_hash_mapping,
                           check_permissions=self._check_perms)
        m._preapproved_stack = self._preapproved_stack
        return m

    def __getitem__(self, addr):
        return self.memory_array[addr]

    def __setitem__(self, addr, v):
        self.memory_array = claripy.Store(self.memory_array, addr, v)

    def __delitem__(self, addr):
        raise Exception("For performance reasons, deletion is not supported. Contact Yan if this needs to change.")
        # Specifically, the above is for two reasons:
        #
        #     1. deleting stuff out of memory doesn't make sense
        #     2. if the page throws a key error, the backer dict is accessed. Thus, deleting things would simply
        #        change them back to what they were in the backer dict

    @property
    def allow_segv(self):
        return self._check_perms and not self.state.scratch.priv and options.STRICT_PAGE_ACCESS in self.state.options

    @property
    def byte_width(self):
        return self.state.arch.byte_width if self.state is not None else 8

    def load(self, addr):
        """
        Load from memory.

        :param addr: Address to start loading.
        :return: Bit vector of value at address
        :rtype: BV
        """
        return self.memory_array[addr]

    def store(self, addr, val):
        """
        Store into memory.

        :param addr: Address to store in.
        :param val: Bit vector value to be stored
        """
        self.addrs.add(addr)
        self.memory_array = claripy.Store(self.memory_array, addr, val)
        print(self.memory_array)

    def contains(self, addr):
        """
        Checks if address has ever been stored to.

        :param addr: Address to store in.
        :param val: Bit vector value to be stored
        """
        return addr in self.addrs
