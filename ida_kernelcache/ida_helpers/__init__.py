"""
A package that is meant to help with the IDA python API
"""

import ida_bytes
import ida_funcs
import ida_segment
import idc

from ida_kernelcache.consts import WORD_SIZE
from ida_kernelcache.exceptions import PhaseException

# Read pointer callback
read_ptr = ida_bytes.get_qword


def get_func_start(ea: int, raise_error: bool = True) -> int:
    f = ida_funcs.get_func(ea)
    if f is None:
        if raise_error:
            raise PhaseException(f'Failed to find function start address of {ea:#x}')
        else:
            return idc.BADADDR

    return f.start_ea


def is_mapped(ea, size=1, value=True):
    """
    Check if the given address is mapped.

    Specify a size greater than 1 to check if an address range is mapped.

    Arguments:
        ea: The linear address to check.

    Options:
        size: The number of bytes at ea to check. Default is 1.
        value: Only consider an address mapped if it has a value. For example, the contents of a
            bss section exist but don't have a static value. If value is False, consider such
            addresses as mapped. Default is True.

    Notes:
        This function is currently a hack: It only checks the first and last byte.
    """
    if size < 1:
        raise ValueError('Invalid argument: size={}'.format(size))
    # HACK: We only check the first and last byte, not all the bytes in between.
    if value:
        return ida_bytes.is_loaded(ea) and (size == 1 or ida_bytes.is_loaded(ea + size - 1))
    else:
        return ida_segment.getseg(ea) and (size == 1 or ida_segment.getseg(ea + size - 1))


def read_word(ea, wordsize=WORD_SIZE) -> int | None:
    """
    Get the word at the given address.

    Words are read using Byte(), Word(), Dword(), or Qword(), as appropriate. Addresses are checked
    using is_mapped(). If the address isn't mapped, then None is returned.
    """
    d = {
        1: ida_bytes.get_wide_byte,
        2: ida_bytes.get_wide_word,
        4: ida_bytes.get_wide_dword,
        8: ida_bytes.get_qword
    }
    if not is_mapped(ea, wordsize):
        return None

    try:
        return d[wordsize](ea)
    except KeyError:
        raise ValueError(f'Invalid argument: wordsize={wordsize}')
