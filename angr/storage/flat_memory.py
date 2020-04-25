import claripy
from collections import ChainMap
import logging

from .. import sim_options as options
from .memory_object import SimMemoryObject
from .paged_memory import  SimPagedMemory

l = logging.getLogger(name=__name__)

#pylint:disable=unidiomatic-typecheck

class SimFlatMemory:
    """
    Represents flat memory.
    """
    def __init__(self, memory_backer=None, permissions_backer=None, check_permissions=None, memory_array=None,
                 addrs=None, paged_memory=None):
        self._memory_backer = { } if memory_backer is None else memory_backer
        self._permissions_backer = permissions_backer # saved for copying
        self._executable_pages = False if permissions_backer is None else permissions_backer[0]
        self._permission_map = { } if permissions_backer is None else permissions_backer[1]
        self.state = None
        self._check_perms = check_permissions

        # reverse mapping
        self._updated_mappings = set()

        self.memory_array = claripy.ArrayV(64, claripy.BVV(0, 8)) if memory_array is None else memory_array
        self.addrs = set() if addrs is None else addrs
        self.paged_memory = SimPagedMemory(memory_backer=memory_backer, permissions_backer=permissions_backer,
                                           check_permissions=check_permissions) if paged_memory is None else paged_memory

    def __getstate__(self):
        return {
            '_memory_backer': self._memory_backer,
            '_permissions_backer': self._permissions_backer,
            '_executable_pages': self._executable_pages,
            '_permission_map': self._permission_map,
            'memory_array': self.memory_array,
            'addrs': self.addrs,
            'paged_memory': self.paged_memory,
            'state': None,
        }

    def __setstate__(self, s):
        self._cowed = set()
        self.__dict__.update(s)

    def branch(self):
        # Bad, hacky fix. Need some way to figure out how to convey state.
        self.paged_memory.state = self.state

        m = SimFlatMemory(memory_backer=self._memory_backer,
                          permissions_backer=self._permissions_backer,
                          memory_array=self.memory_array,
                          paged_memory=self.paged_memory.branch(),
                          addrs=self.addrs,)
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

    def load(self, addr, size):
        """
        Load from memory.

        :param addr: Address to start loading.
        :param size: Size of value to be loaded.
        :return: Bit vector of value at address
        :rtype: BV
        """
        ret = self.state.solver.simplify(self.memory_array[addr])
        for byte in range(1, size):
            ret = self.state.solver.simplify(self.memory_array[addr + byte]).concat(ret)
        return ret

    def store(self, addr, val, size):
        """
        Store into memory.

        :param addr: Address to store in.
        :param size: Size of value to be stored.
        :param val: Bit vector value to be stored
        """
        # TODO: Fix incorrect behavior of addrs
        self.addrs.add(addr)
        for byte in range(0, size):
            self.memory_array = claripy.Store(self.memory_array, addr + byte,
                                              val[(byte + 1) * self.byte_width - 1:byte * self.byte_width])

    def contains(self, addr):
        """
        Checks if address has ever been stored to.

        :param addr: Address to store in.
        :param val: Bit vector value to be stored
        """
        return addr in self.addrs

    def _mark_updated_mapping(self, d, m):
        print("Should not occur")
        self.paged_memory._mark_updated_mapping(d, m)

    def _update_range_mappings(self, actual_addr, cnt, size):
        print("Should not occur")
        self.paged_memory._update_range_mappings(actual_addr, cnt, size)

    def _update_mappings(self, actual_addr, cnt):
        print("Should not occur")
        self.paged_memory._update_mappings(actual_addr, cnt)

    def get_symbolic_addrs(self):
        print("WEW9")
        return self.paged_memory.get_symbolic_addrs()

    def addrs_for_name(self, n):
        print("WEW8")
        return self.paged_memory.addrs_for_name(n)

    def addrs_for_hash(self, h):
        print("WEW7")
        return self.paged_memory.addrs_for_hash(h)

    def memory_objects_for_name(self, n):
        print("WEW6")
        return self.paged_memory.memory_objects_for_name(n)

    def memory_objects_for_hash(self, n):
        print("WEW4")
        return self.paged_memory.memory_objects_for_hash(n)

    def permissions(self, addr, permissions=None):
        return self.state.solver.BVV(1, 3)
        # Bad, hacky fix. Need some way to figure out how to convey state.
        self.paged_memory.state = self.state
        return self.paged_memory.permissions(addr, permissions)

    def map_region(self, addr, length, permissions, init_zero=False):
        print("WEW1")
        self.paged_memory.map_region(addr, length, permissions, init_zero)

    def unmap_region(self, addr, length):
        print("WEW2")
        self.paged_memory.unmap_region(addr, length)

    def flush_pages(self, white_list):
        print("WEW3")
        return self.paged_memory.flush_pages(white_list)

    def store_memory_object(self, mo, overwrite=True):
        """
        This function optimizes a large store by storing a single reference to the :class:`SimMemoryObject` instead of
        one for each byte.

        :param mo: the memory object to store
        """
        print("wooh3")
        self.paged_memory.store_memory_object(mo, overwrite)

    def replace_memory_object(self, old, new_content):
        """
        Replaces the memory object `old` with a new memory object containing `new_content`.

        :param old:         A SimMemoryObject (i.e., one from :func:`memory_objects_for_hash()` or :func:`
                            memory_objects_for_name()`).
        :param new_content: The content (claripy expression) for the new memory object.
        :returns: the new memory object
        """
        print("wooh1")
        return self.paged_memory.replace_memory_object(old, new_content)

    def replace_all(self, old, new):
        """
        Replaces all instances of expression `old` with expression `new`.

        :param old: A claripy expression. Must contain at least one named variable (to make it possible to use the
                    name index for speedup).
        :param new: The new variable to replace it with.
        """
        print("wooh2")
        self.paged_memory.replace_all(old, new)

    def contains_no_backer(self, addr):
        """
        Tests if the address is contained in any page of paged memory, without considering memory backers.

        :param int addr: The address to test.
        :return: True if the address is included in one of the pages, False otherwise.
        :rtype: bool
        """
        print("wooh4")
        return self.paged_memory.contains_no_backer(addr)

    def keys(self):
        print("wooh5")
        return self.paged_memory.keys()

    def __len__(self):
        print("wooh6")
        return len(self.addrs)

    def changed_bytes(self, other):
        print("wooh7")
        return self.paged_memory.changed_bytes(other)

    @property
    def allow_segv(self):
        print("wooh8")
        return self.paged_memory.allow_segv

    @property
    def byte_width(self):
        return self.paged_memory.byte_width

    def load_objects(self, addr, num_bytes, ret_on_segv=False):
        print("wooh10")
        """
        Load memory objects from paged memory.

        :param addr: Address to start loading.
        :param num_bytes: Number of bytes to load.
        :param bool ret_on_segv: True if you want load_bytes to return directly when a SIGSEV is triggered, otherwise
                                 a SimSegfaultError will be raised.
        :return: list of tuples of (addr, memory_object)
        :rtype: tuple
        """
        return self.paged_memory.load_objects(addr, num_bytes, ret_on_segv)
