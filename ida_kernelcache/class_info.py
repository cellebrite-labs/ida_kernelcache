"""

ida_kernelcache/class_info.py
Author: Brandon Azad

This module defines the ClassInfo class, which stores information about a C++ class in the
kernelcache. It also provides the function collect_class_info() to scan the kernelcache for
information about C++ classes and populate global variables with the result.
"""
import idc

from ida_kernelcache import (
    ida_utilities as idau,
    consts
)


class ClassInfo(object):
    """
    Python class to store C++ class information from KernelCache.
    """

    def __init__(self, classname: str, metaclass: int, class_size: int, superclass_name: str, meta_superclass: int, vtable_ea: int = idc.BADADDR, vtable_end_ea: int = idc.BADADDR):
        self.superclass = None
        self.subclasses = set()
        self.classname = classname
        self.metaclass_ea = metaclass
        self.class_size = class_size
        self.superclass_name = superclass_name
        self.meta_superclass = meta_superclass

        # There are several classes where vtable information is
        self.vtable_ea = vtable_ea
        self.vtable_end_ea = vtable_end_ea

    def __repr__(self):
        def hex(x):
            if x is None:
                return repr(None)
            return f'{x:#x}'

        return 'ClassInfo({!r}, {}, {}, {}, {}, {!r}, {})'.format(
            self.classname, hex(self.metaclass_ea), hex(self.vtable_ea),
            self.vtable_length, self.class_size, self.superclass_name,
            hex(self.meta_superclass))

    @property
    def vtable_length(self) -> int:
        """
        This property is the number of bytes for the whole vtable
        """
        return self.vtable_end_ea - self.vtable_ea

    @property
    def vtable_methods_start(self) -> int:
        """
        The EA of the first actual method in the vtable
        """
        return self.vtable_ea + consts.VTABLE_FIRST_METHOD_OFFSET

    @property
    def vtable_num_methods(self) -> int:
        assert self.vtable_length % consts.WORD_SIZE == 0, f'Invalid vtable length {self.vtable_length} for {self.classname}!'
        return self.vtable_length // consts.WORD_SIZE

    def ancestors(self, inclusive: bool = False) -> ['ClassInfo', None, None]:
        """A generator over all direct or indircet superclasses of this class.

        Ancestors are returned in order from root (most distance) to superclass (closest), and the
        class itself is not returned.

        Options:
            inclusive: If True, then this class is included in the iteration. Default is False.
        """
        if self.superclass:
            for ancestor in self.superclass.ancestors(inclusive=True):
                yield ancestor
        if inclusive:
            yield self

    def descendants(self, inclusive: bool = False) -> ['ClassInfo', None, None]:
        """A generator over all direct or indirect subclasses of this class.

        Descendants are returned in descending depth-first order: first a subclass will be
        returned, then all of its descendants, before going on to the next subclass of this class.

        Options:
            inclusive: If True, then this class is included in the iteration. Default is False.
        """
        if inclusive:
            yield self
        for subclass in self.subclasses:
            for descendant in subclass.descendants(inclusive=True):
                yield descendant


class ClassInfoMap:
    """
    Allows us to index the ClassInfo instances both by classname and by metaclass ea
    The usage is simple, but don't confuse this map with a standard dictionary because except of some helper magic methods
    that I have overwritten it does not behave like a normal dict

    Wrong usage would lead to TypeError being raised
    """

    def __init__(self):
        super().__init__()
        # A global map from metaclass_ea to ClassInfo objects.
        self.metaclass_ea_to_class_info: dict[int, ClassInfo] = {}

        # A global map from class names to ClassInfo objects.
        self.classname_to_class_info: dict[str, ClassInfo] = {}
        self._key_type_to_dict: dict[type, dict] = {
            int: self.metaclass_ea_to_class_info,
            str: self.classname_to_class_info
        }

    def _get_dict_from_type(self, key_type: type) -> dict:
        if key_type not in self._key_type_to_dict:
            raise TypeError(f'{self.__class__.__name__} allows int or str keys only!')
        return self._key_type_to_dict[key_type]

    def _get_dict_from_key(self, key: int | str) -> dict:
        return self._get_dict_from_type(type(key))

    def __setitem__(self, key: tuple[str, int], value):
        if not isinstance(key, tuple) or len(key) != 2:
            raise TypeError(f'Every key in this mapping must be of type: tuple[str, int]')

        self.metaclass_ea_to_class_info.__setitem__(key[1], value)
        self.classname_to_class_info.__setitem__(key[0], value)

    def __getitem__(self, key):
        d = self._get_dict_from_key(key)
        return d.__getitem__(key)

    def __contains__(self, key):
        d = self._get_dict_from_key(key)
        return d.__contains__(key)

    def __len__(self):
        assert len(self.metaclass_ea_to_class_info) == len(self.classname_to_class_info), 'Invalid state, inner mappings does not match in length'
        return self.metaclass_ea_to_class_info.__len__()

    def __bool__(self):
        return all(bool(d) for d in self._key_type_to_dict.values())

    def clear(self):
        for d in self._key_type_to_dict.values():
            d.clear()

    def add_classinfo(self, new_class_info: ClassInfo):
        """
        Just a helper method to index this class info in this map by both its classname and its metaclass_ea
        """
        assert new_class_info.classname, 'invalid classname'
        assert new_class_info.metaclass_ea, 'invalid metaclass_ea'

        self[(new_class_info.classname, new_class_info.metaclass_ea)] = new_class_info

    def items_by_type(self, key_type: type):
        d = self._get_dict_from_type(key_type)
        return d.items()
