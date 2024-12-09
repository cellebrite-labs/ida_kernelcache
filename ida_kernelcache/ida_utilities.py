# def _insn_op_stroff_700(insn, n, sid, delta):
#     """
#     A wrapper of idc.op_stroff for IDA 7.
#     """
#     return idc.op_stroff(insn, n, sid, delta)
#
#
# insn_op_stroff = _insn_op_stroff_700
#
# _FF_FLAG_FOR_SIZE = {
#     1: idc.FF_BYTE,
#     2: idc.FF_WORD,
#     4: idc.FF_DWORD,
#     8: idc.FF_QWORD,
#     16: idc.FF_OWORD,
# }


# def word_flag(wordsize=WORD_SIZE):
#     """
#     Get the FF_xxxx flag for the given word size."""
#     return _FF_FLAG_FOR_SIZE.get(wordsize, 0)

# class objectview(object):
#     """
#     A class to present an object-like view of a struct."""
#
#     # https://goodcode.io/articles/python-dict-object/
#     def __init__(self, fields, addr, size):
#         self.__dict__ = fields
#         self.__addr = addr
#         self.__size = size
#
#     def __int__(self):
#         return self.__addr
#
#     def __len__(self):
#         return self.__size
#
#
# def _read_struct_member_once(ea, flags, size, member_sid, member_size, asobject):
#     """
#     Read part of a struct member for _read_struct_member."""
#     if ida_bytes.is_byte(flags):
#         return read_word(ea, 1), 1
#     elif ida_bytes.is_word(flags):
#         return read_word(ea, 2), 2
#     elif ida_bytes.is_dword(flags):
#         return read_word(ea, 4), 4
#     elif ida_bytes.is_qword(flags):
#         return read_word(ea, 8), 8
#     elif ida_bytes.is_oword(flags):
#         return read_word(ea, 16), 16
#     elif ida_bytes.is_strlit(flags):
#         return idc.get_bytes(ea, size), size
#     elif ida_bytes.is_float(flags):
#         return idc.Float(ea), 4
#     elif ida_bytes.is_double(flags):
#         return idc.Double(ea), 8
#     elif ida_bytes.is_struct(flags):
#         value = read_struct(ea, sid=member_sid, asobject=asobject)
#         return value, member_size
#     return None, size
#
#
# def _read_struct_member(struct, sid, union, ea, offset, name, size, asobject):
#     """
#     Read a member into a struct for read_struct."""
#     flags = idc.get_member_flag(sid, offset)
#     assert flags != -1
#     # Extra information for parsing a struct.
#     member_sid, member_ssize = None, None
#     if ida_bytes.is_struct(flags):
#         member_sid = idc.get_member_strid(sid, offset)
#         member_ssize = ida_struct.get_struc_size(member_sid)
#     # Get the address of the start of the member.
#     member = ea
#     if not union:
#         member += offset
#     # Now parse out the value.
#     array = []
#     processed = 0
#     while processed < size:
#         value, read = _read_struct_member_once(member + processed, flags, size, member_sid,
#                                                member_ssize, asobject)
#         assert size % read == 0
#         array.append(value)
#         processed += read
#     if len(array) == 1:
#         value = array[0]
#     else:
#         value = array
#     struct[name] = value
#
#
# def read_struct(ea, struct=None, sid=None, members=None, asobject=False):
#     """
#     Read a structure from the given address.
#
#     This function reads the structure at the given address and converts it into a dictionary or
#     accessor object.
#
#     Arguments:
#         ea: The linear address of the start of the structure.
#
#     Options:
#         sid: The structure ID of the structure type to read.
#         struct: The name of the structure type to read.
#         members: A list of the names of the member fields to read. If members is None, then all
#             members are read. Default is None.
#         asobject: If True, then the struct is returned as a Python object rather than a dict.
#
#     One of sid and struct must be specified.
#     """
#     # Handle sid/struct.
#     if struct is not None:
#         sid2 = ida_struct.get_struc_id(struct)
#         if sid2 == idc.BADADDR:
#             raise ValueError('Invalid struc name {}'.format(struct))
#         if sid is not None and sid2 != sid:
#             raise ValueError('Invalid arguments: sid={}, struct={}'.format(sid, struct))
#         sid = sid2
#     else:
#         if sid is None:
#             raise ValueError('Invalid arguments: sid={}, struct={}'.format(sid, struct))
#         if ida_struct.get_struc_name(sid) is None:
#             raise ValueError('Invalid struc id {}'.format(sid))
#     # Iterate through the members and add them to the struct.
#     union = idc.is_union(sid)
#     struct = {}
#     for offset, name, size in idautils.StructMembers(sid):
#         if members is not None and name not in members:
#             continue
#         _read_struct_member(struct, sid, union, ea, offset, name, size, asobject)
#     if asobject:
#         struct = objectview(struct, ea, ida_struct.get_struc_size(sid))
#     return struct
#
#
# def null_terminated(string):
#     """
#     Extract the NULL-terminated C string from the given array of bytes."""
#     return string.split(b'\0', 1)[0].decode()
#
#
# def _fix_unrecognized_function_insns(func):
#     # Undefine every instruction that IDA does not recognize within the function
#     while idc.find_func_end(func) == idc.BADADDR:
#         func_properties = ida_funcs.func_t(func)
#         ida_funcs.find_func_bounds(func_properties, ida_funcs.FIND_FUNC_DEFINE)
#         unrecognized_insn = func_properties.end_ea
#         if unrecognized_insn == 0:
#             _log(1, "Could not find unrecognized instructions for function at {:#x}", func)
#             return False
#
#         # We found an unrecognized instruction, lets undefine it and explicitly make an instruction out of it!
#         unrecognized_insn_end = ida_bytes.get_item_end(unrecognized_insn)
#         _log(1, 'Undefining item {:#x} - {:#x}', unrecognized_insn, unrecognized_insn_end)
#         ida_bytes.del_items(unrecognized_insn, ida_bytes.DELIT_EXPAND)
#         if idc.create_insn(unrecognized_insn) == 0:
#             _log(1, "Could not convert data at {:#x} to instruction", unrecognized_insn)
#             return False
#
#     return True
#
#
# def _convert_address_to_function(func):
#     """
#     Convert an address that IDA has classified incorrectly into a proper function."""
#     # If everything goes wrong, we'll try to restore this function.
#     orig = idc.first_func_chunk(func)
#     if idc.find_func_end(func) == idc.BADADDR:
#         # Could not find function end, probably because IDA parsed an instruction
#         # in the middle of the function incorrectly as data. Lets try to fix the relevant insns.
#         _fix_unrecognized_function_insns(func)
#
#     else:
#         # Just try removing the chunk from its current function. IDA can add it to another function
#         # automatically, so make sure it's removed from all functions by doing it in loop until it
#         # fails.
#         for i in range(1024):
#             if not idc.remove_fchunk(func, func):
#                 break
#     # Now try making a function.
#     if ida_funcs.add_func(func) != 0:
#         return True
#     # This is a stubborn chunk. Try recording the list of chunks, deleting the original function,
#     # creating the new function, then re-creating the original function.
#     if orig != idc.BADADDR:
#         chunks = list(idautils.Chunks(orig))
#         if ida_funcs.del_func(orig) != 0:
#             # Ok, now let's create the new function, and recreate the original.
#             if ida_funcs.add_func(func) != 0:
#                 if ida_funcs.add_func(orig) != 0:
#                     # Ok, so we created the functions! Now, if any of the original chunks are not
#                     # contained in a function, we'll abort and undo.
#                     if all(idaapi.get_func(start) for start, end in chunks):
#                         return True
#             # Try to undo the damage.
#             for start, _ in chunks:
#                 ida_funcs.del_func(start)
#     # Everything we've tried so far has failed. If there was originally a function, try to restore
#     # it.
#     if orig != idc.BADADDR:
#         _log(0, 'Trying to restore original function {:#x}', orig)
#         ida_funcs.add_func(orig)
#     return False
#
#
# def is_function_start(ea):
#     """
#     Return True if the address is the start of a function."""
#     return idc.get_func_attr(ea, idc.FUNCATTR_START) == ea
#
#
# def force_function(addr):
#     """
#     Ensure that the given address is a function type, converting it if necessary."""
#     if is_function_start(addr):
#         return True
#     return _convert_address_to_function(addr)
#
##
#
# def WindowWords(start, end, window_size, wordsize=WORD_SIZE):
#     """
#     A generator to iterate over a sliding window of data words in the given address range.
#
#     The iterator returns a stream of tuples (window, ea) for each word in the address range. The
#     window is a deque of the window_size words at address ea. The deque is owned by the generator
#     and its contents will change between iterations.
#     """
#     words = ReadWords(start, end, wordsize=wordsize)
#     window = deque([next(words) for _ in range(window_size)], maxlen=window_size)
#     addr = start
#     yield window, addr
#     for word in words:
#         window.append(word)
#         addr += wordsize
#         yield window, addr
#
#
# def struct_create(name, union=False):
#     """
#     Create an IDA struct with the given name, returning the SID."""
#     # AddStrucEx is documented as returning -1 on failure, but in practice it seems to return
#     # BADADDR.
#     union = 1 if union else 0
#     sid = idc.add_struc(-1, name, union)
#     if sid in (-1, idc.BADADDR):
#         return None
#     return sid
#
#
# def struct_open(name, create=False, union=None):
#     """
#     Get the SID of the IDA struct with the given name, optionally creating it."""
#     sid = ida_struct.get_struc_id(name)
#     if sid == idc.BADADDR:
#         if not create:
#             return None
#         sid = struct_create(name, union=bool(union))
#     elif union is not None:
#         is_union = bool(idc.is_union(sid))
#         if union != is_union:
#             return None
#     return sid
#
#
# def struct_member_offset(sid, name):
#     """
#     A version of IDA's GetMemberOffset() that also works with unions."""
#     struct = idaapi.get_struc(sid)
#     if not struct:
#         return None
#     member = idaapi.get_member_by_name(struct, name)
#     if not member:
#         return None
#     return member.soff
#
#
# def struct_add_word(sid, name, offset, size, count=1):
#     """
#     Add a word (integer) to a structure.
#
#     If sid is a union, offset must be -1.
#     """
#     return idc.add_struc_member(sid, name, offset, idc.FF_DATA | word_flag(size), -1, size * count)
#
#
# def struct_add_ptr(sid, name, offset, count=1, type=None):
#     """
#     Add a pointer to a structure.
#
#     If sid is a union, offset must be -1.
#     """
#     ptr_flag = idc.FF_DATA | word_flag(WORD_SIZE) | ida_bytes.off_flag()
#     ret = idc.add_struc_member(sid, name, offset, ptr_flag, 0, WORD_SIZE)
#     if ret == 0 and type is not None:
#         if offset == -1:
#             offset = struct_member_offset(sid, name)
#             assert offset is not None
#         mid = idc.get_member_id(sid, offset)
#         idc.SetType(mid, type)
#     return ret
#
#
# def struct_add_struct(sid, name, offset, msid, count=1):
#     """
#     Add a structure member to a structure.
#
#     If sid is a union, offset must be -1.
#     """
#     size = ida_struct.get_struc_size(msid)
#     return idc.add_struc_member(sid, name, offset, idc.FF_DATA | ida_bytes.FF_STRUCT, msid, size * count)
