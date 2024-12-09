import idautils
import idc
import re

from ida_kernelcache.consts import WORD_SIZE
from ida_kernelcache.exceptions import AlignmentError
from . import read_word, is_mapped

__all__ = ['Addresses', 'ReadWords', 'Instructions']


def DataRefsToWithSegmentFilter(ea: int, pattern: str) -> (int, None, None):
    for xref_ea in idautils.DataRefsTo(ea):
        if re.match(pattern, idc.get_segm_name(xref_ea)):
            yield xref_ea


def _addresses(start, end, step, partial, aligned):
    """
    A generator to iterate over the addresses in an address range.
    """
    addr = start
    end_full = end - step + 1
    while addr < end_full:
        yield addr
        addr += step
    if addr != end:
        if aligned:
            raise AlignmentError(end)
        if addr < end and partial:
            yield addr


def _mapped_addresses(addresses, step, partial, allow_unmapped):
    """
    Wrap an _addresses generator with a filter that checks whether the addresses are mapped.
    """
    for addr in addresses:
        start_is_mapped = is_mapped(addr)
        end_is_mapped = is_mapped(addr + step - 1)
        fully_mapped = start_is_mapped and end_is_mapped
        allowed_partial = partial and (start_is_mapped or end_is_mapped)
        # Yield the value if it's sufficiently mapped. Otherwise, break if we stop at an
        # unmapped address.
        if fully_mapped or allowed_partial:
            yield addr
        elif not allow_unmapped:
            break


def Addresses(start, end=None, step=1, length=None, partial=False, aligned=False, unmapped=True, allow_unmapped=False):
    """
    A generator to iterate over the addresses in an address range.

    Arguments:
        start: The start of the address range to iterate over.

    Options:
        end: The end of the address range to iterate over.
        step: The amount to step the address by each iteration. Default is 1.
        length: The number of elements of size step to iterate over.
        partial: If only part of the element is in the address range, or if only part of the
            element is mapped, return it anyway. Default is False. This option is only meaningful
            if aligned is False or if some address in the range is partially unmapped.
        aligned: If the end address is not aligned with an iteration boundary, throw an
            AlignmentError.
        unmapped: Don't check whether an address is mapped or not before returning it. This option
            always implies allow_unmapped. Default is True.
        allow_unmapped: Don't stop iteration if an unmapped address is encountered (but the address
            won't be returned unless unmapped is also True). Default is False. If partial is also
            True, then a partially mapped address will be returned and then iteration will stop.
    """
    # HACK: We only check the first and last byte, not all the bytes in between.
    # Validate step.
    if step < 1:
        raise ValueError('Invalid arguments: step={}'.format(step))
    # Set the end address.
    if length is not None:
        end_addr = start + length * step
        if end is not None and end != end_addr:
            raise ValueError('Invalid arguments: start={}, end={}, step={}, length={}'
                             .format(start, end, step, length))
        end = end_addr
    if end is None:
        raise ValueError('Invalid arguments: end={}, length={}'.format(end, length))
    addresses = _addresses(start, end, step, partial, aligned)
    # If unmapped is True, iterate over all the addresses. Otherwise, we will check that addresses
    # are properly mapped with a wrapper.
    if unmapped:
        return addresses
    else:
        return _mapped_addresses(addresses, step, partial, allow_unmapped)


def ReadWords(start, end, step=WORD_SIZE, wordsize=WORD_SIZE, addresses=False):
    """
    A generator to iterate over the data words in the given address range.

    The iterator returns a stream of words or tuples for each mapped word in the address range.
    Words are read using read_word(). Iteration stops at the first unmapped word.

    Arguments:
        start: The start address.
        end: The end address.

    Options:
        step: The number of bytes to advance per iteration. Default is WORD_SIZE.
        wordsize: The word size to read, in bytes. Default is WORD_SIZE.
        addresses: If true, then the iterator will return a stream of tuples (word, ea) for each
            mapped word in the address range. Otherwise, just the word itself will be returned.
            Default is False.
    """
    for addr in Addresses(start, end, step=step, unmapped=True):
        word = read_word(addr, wordsize)
        if word is None:
            break
        if addresses:
            yield word, addr
        else:
            yield word


def _instructions_by_range(start, end):
    """
    A generator to iterate over instructions in a range."""
    pc = start
    while pc < end:
        insn = idautils.DecodeInstruction(pc)
        if insn is None:
            break
        next_pc = pc + insn.size
        """
        Sometimes IDA coalesces instruction and the lenght would take us over the end.
        One cannot know in advance in this is the case. Hence, disabling the check ...
        if next_pc > end:
            raise AlignmentError(end)
        """
        yield insn
        pc = next_pc


def _instructions_by_count(pc, count):
    """
    A generator to iterate over a specified number of instructions."""
    for i in range(count):
        insn = idautils.DecodeInstruction(pc)
        if insn is None:
            break
        yield insn
        pc += insn.size


def Instructions(start, end=None, count=None):
    """
    A generator to iterate over instructions.

    Instructions are decoded using IDA's DecodeInstruction(). If an address range is specified and
    the end of the address range does not fall on an instruction boundary, raises an
    AlignmentError.

    Arguments:
        start: The linear address from which to start decoding instructions.

    Options:
        end: The linear address at which to stop, exclusive.
        count: The number of instructions to decode.

    Notes:
        Exactly one of end and count must be specified.
    """
    if (end is not None and count is not None) or (end is None and count is None):
        raise ValueError('Invalid arguments: end={}, count={}'.format(end, count))
    if end is not None:
        return _instructions_by_range(start, end)
    else:
        return _instructions_by_count(start, count)
