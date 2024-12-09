import idc
import idaapi
import idautils
import logging

import ida_kernelcache.ida_helpers as ida_helpers
import ida_kernelcache.ida_helpers.generators as generators

# IDK where IDA defines these.
_MEMOP_PREINDEX = 0x20
_MEMOP_POSTINDEX = 0x80
_MEMOP_WBINDEX = _MEMOP_PREINDEX | _MEMOP_POSTINDEX

log = logging.getLogger(__name__)


class _Regs(object):
    """A set of registers for _emulate_arm64."""

    class _Unknown:
        """A wrapper class indicating that the value is unknown."""

        def __add__(self, other):
            return _Regs.Unknown

        def __radd__(self, other):
            return _Regs.Unknown

        def __bool__(self):
            return False

        def __and__(self, other):
            return _Regs.Unknown

        def __or__(self, other):
            return _Regs.Unknown

    _reg_names = idautils.GetRegisterList()
    Unknown = _Unknown()

    def __init__(self):
        self.clearall()

    def clearall(self):
        self._regs = {}

    def clear(self, reg):
        try:
            del self._regs[self._reg(reg)]
        except KeyError:
            pass

    def _reg(self, reg):
        if isinstance(reg, int):
            reg = _Regs._reg_names[reg]
        return reg

    def __getitem__(self, reg):
        try:
            return self._regs[self._reg(reg)]
        except:
            return _Regs.Unknown

    def __setitem__(self, reg, value):
        if value is None or value is _Regs.Unknown:
            self.clear(self._reg(reg))
        else:
            self._regs[self._reg(reg)] = value & 0xffffffffffffffff


def emulate_arm64(start, end, on_BL=None, on_RET=None):
    """A very basic partial Arm64 emulator that does just enough to find OSMetaClass
    information."""
    # Super basic emulation.
    reg = _Regs()

    def load(addr, dtyp):
        if not addr:
            return None
        if dtyp == idaapi.dt_qword:
            size = 8
        elif dtyp == idaapi.dt_dword:
            size = 4
        else:
            return None
        return ida_helpers.read_word(addr, size)

    def cleartemps():
        for t in ['X{}'.format(i) for i in range(0, 19)]:
            reg.clear(t)

    for insn in generators.Instructions(start, end):
        log.debug(f'Processing instruction {insn.ea:#x}')
        mnem = insn.get_canon_mnem()
        if mnem == 'ADRP' or mnem == 'ADR' or mnem == 'ADRL':
            reg[insn.Op1.reg] = insn.Op2.value
        elif mnem == 'ADD' and insn.Op2.type == idc.o_reg and insn.Op3.type == idc.o_imm:
            reg[insn.Op1.reg] = reg[insn.Op2.reg] + insn.Op3.value
        elif mnem == 'NOP':
            pass
        elif mnem == 'PAC':
            pass
        elif mnem == 'MOV' and insn.Op2.type == idc.o_imm:
            reg[insn.Op1.reg] = insn.Op2.value
        elif mnem == 'MOV' and insn.Op2.type == idc.o_reg:
            reg[insn.Op1.reg] = reg[insn.Op2.reg]
        elif mnem == 'MOVK' and insn.Op2.type == idc.o_imm:
            shift = insn.Op2.specval
            val = insn.Op2.value
            change_mask = 0xffff << shift
            keep_mask = ((1 << 64) - 1) ^ change_mask
            reg[insn.Op1.reg] &= keep_mask
            reg[insn.Op1.reg] |= ((val << shift) & change_mask)
        elif mnem == 'RET':
            if on_RET:
                on_RET(reg)
            break
        elif (mnem == 'STP' or mnem == 'LDP') and insn.Op3.type == idc.o_displ:
            if insn.auxpref & _MEMOP_WBINDEX:
                reg[insn.Op3.reg] = reg[insn.Op3.reg] + insn.Op3.addr
            if mnem == 'LDP':
                reg.clear(insn.Op1.reg)
                reg.clear(insn.Op2.reg)
        elif (mnem == 'STR' or mnem == 'LDR') and not insn.auxpref & _MEMOP_WBINDEX:
            if mnem == 'LDR':
                if insn.Op2.type == idc.o_displ:
                    reg[insn.Op1.reg] = load(reg[insn.Op2.reg] + insn.Op2.addr, insn.Op1.dtype)
                else:
                    reg.clear(insn.Op1.reg)
        elif mnem == 'BL' and insn.Op1.type == idc.o_near:
            if on_BL:
                on_BL(insn.Op1.addr, reg)
            cleartemps()
        else:
            log.debug(f'Unrecognized instruction at address {insn.ea:#x}')
            reg.clearall()
