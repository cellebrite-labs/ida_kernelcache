import ida_hexrays
import ida_ua
import idaapi
import idautils
import idc

from ida_kernelcache import consts
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.ida_helpers import decompiler, generators
import ida_kernelcache.ida_helpers as ida_helpers
from .base_phase import BasePhase


class CollectVtables(BasePhase):
    """
    This phase depends on the CollectClasses phase and must run after it
    """
    GET_METACLASS_FUNC_SIZE = 16

    def __init__(self, kc):
        super().__init__(kc)

        # Build a mapping from OSMetaClass instances to virtual method tables.
        # self._metaclass_to_vtable_builder = OneToOneMapFactory()

        # Track metaclass ea that we could not find the ::getMetaClass
        self._associated_vtables: set[int] = set()
        self._not_found_set: set[int] = set()
        self._metaclass_ea_to_getmetaclass_ea: dict[int, int] = {}
        self.X0_REGISTER_INDEX = idautils.GetRegisterList().index('X0')

    def run(self):

        # TODO: implement Phase Dependencies?
        if not self._kc.class_info_map:
            raise PhaseException(f"There are no entries in the KernelCache.classes dictionary.. consider running "
                                 f"CollectClasses phase before {self.__class__}")
        self._collect_getmetaclass_methods()
        self._collect_vtables_new()

    def _collect_getmetaclass_methods(self) -> None:
        num_fallback_findings = 0
        num_multiple = 0
        self.log.info('Searching for ::getMetaClass methods..')

        for metaclass_ea, info in self._kc.class_info_map.items_by_type(key_type=int):
            candidates = set()
            for xref_ea in idautils.DataRefsTo(metaclass_ea):
                xref_func = idaapi.get_func(xref_ea)

                # Skip xrefs that are not part of a function or are too big to be valid candidates
                if xref_func is None:
                    continue

                potential_func_start = idaapi.prev_head(xref_ea, 0)
                # Prefer to use ctree inspection to determine this
                if xref_func.start_ea == potential_func_start and xref_func.size() == self.GET_METACLASS_FUNC_SIZE:
                    if self._is_getmetaclass_method(xref_ea, metaclass_ea):
                        candidates.add(xref_func.start_ea)
                        continue

                # When IDA messes up the initial auto-analysis we have to resort to the dissasembly
                if self._is_getmetaclass_method_fallback(potential_func_start, metaclass_ea):
                    num_fallback_findings += 1
                    candidates.add(potential_func_start)

            if len(candidates) == 1:
                self._metaclass_ea_to_getmetaclass_ea[metaclass_ea] = candidates.pop()
                self.log.debug(f'Found {info.classname}::getMetaClass at {self._metaclass_ea_to_getmetaclass_ea[metaclass_ea]:#x} metaclass_ea {metaclass_ea:#x}')
            elif len(candidates) > 1:
                self.log.error(f'Found multiple candidates for {info.classname}::getMetaClass! {", ".join(f"{x:#x}" for x in candidates)}')
                num_multiple += 1
            else:
                self._not_found_set.add(metaclass_ea)

        # There are a small amount of classes which seems like we cannot associate them with a vtable (simply because it doesn't exist in the binary..?)
        # I'm not sure when the compiler decides not to yield vtables in the binary,
        # I guess this is some sort of optimization where an intermediate class (in the inheritance tree) does not override and method.
        for metaclass_ea in self._not_found_set:
            # TODO: check if all of the references to this metaclass_ea is in __mod_init or __mod_term. Don't print and error if this is the case
            info = self._kc.class_info_map[metaclass_ea]
            self.log.warning(f'Failed to find {info.classname}::getMetaClass! metaclass_ea {metaclass_ea:#x}')

        # Log statistics to the user
        self.log.info(f'Found {len(self._metaclass_ea_to_getmetaclass_ea)}/{len(self._kc.class_info_map)}! '
                      f'fallback: {num_fallback_findings} not found: {len(self._not_found_set)} multiple: {num_multiple}')

    def _is_getmetaclass_method(self, xref_ea: int, metaclass_ea: int) -> bool:
        cfunc = ida_hexrays.decompile(xref_ea)
        if cfunc is None:
            raise PhaseException(f'hexrays decompilation failed! ea:{xref_ea:#x}')

        root: ida_hexrays.cinsn_t = cfunc.body

        if root.op == ida_hexrays.cit_block and len(root.cblock) == 1 and root.cblock[0].op == ida_hexrays.cit_return:
            return_statement: ida_hexrays.creturn_t = root.cblock[0].creturn
            expr = decompiler.traverse_casts_or_ref_branch(return_statement.expr)
            return expr.op == ida_hexrays.cot_obj and expr.obj_ea == metaclass_ea

    def _is_getmetaclass_method_fallback(self, potential_func_start: int, metaclass_ea: int) -> bool:
        """
        Every ::getMetaClass method should look the following set of instructions
        BTI c
        ADRL X0, metaclass_ea
        RET
        """
        mnemonics = [
            'BTI',
            'ADRL',
            'RET'
        ]

        for mnem, insn in zip(mnemonics, generators.Instructions(potential_func_start, count=3)):
            insn: ida_ua.insn_t
            if mnem != insn.get_canon_mnem():
                return False

            match mnem:
                case 'BTI':
                    if insn.Op1.value != 0x63:  # 'c'
                        return False

                case 'ADRL':
                    if insn.Op1.reg != self.X0_REGISTER_INDEX or insn.Op2.value != metaclass_ea:
                        return False
        return True

    def _collect_vtables_new(self):
        for metaclass_ea, getmetaclass_ea in self._metaclass_ea_to_getmetaclass_ea.items():
            classinfo = self._kc.class_info_map[metaclass_ea]

            if classinfo.classname == 'OSMetaClass':
                # TODO: OSMetaClass::getMetaClass is referenced in all of the other MetaClasses
                self.log.warning('Currently not collecting *::MetaClass vtables (needs to be implemented)')
                continue

            candidates = list(generators.DataRefsToWithSegmentFilter(getmetaclass_ea, r'.*__const$'))

            # Look for the vtable that references this method!
            if len(candidates) == 1:
                vtable_ea = candidates[0] - consts.VTABLE_GETMETACLASS_OFFSET
                if vtable_ea in self._associated_vtables:
                    self.log.warning(f'Vtable {vtable_ea:#x} is already associated with some other class!')
                else:
                    self._associated_vtables.add(vtable_ea)

                # Count the number of methods in this vtable to determine its length
                num_vtable_methods = consts.INITIAL_NUM_VTABLE_METHODS
                for vmethod_ea in generators.ReadWords(candidates[0], idc.get_segm_end(vtable_ea)):
                    # Stop on the first NULL
                    if not vmethod_ea:
                        break

                    # If this happens this is probably because IDA auto-analysis failed to determine function boundaries correctly
                    if ida_helpers.get_func_start(vmethod_ea, raise_error=False) != vmethod_ea:
                        # TODO: solve this by fixing the __noreturn attribute missing from panic functions upon initial analysis
                        self.log.debug(f'Virtual method {num_vtable_methods + 1} points to {vmethod_ea:#x} which is not the start of a function!')

                    num_vtable_methods += 1

                vtable_end_ea = vtable_ea + num_vtable_methods * consts.WORD_SIZE + consts.VTABLE_FIRST_METHOD_OFFSET
                self.log.debug(f'Found vtable of {classinfo.classname} {vtable_ea:#x}-{vtable_end_ea:#x} num methods:{num_vtable_methods}')

                # TODO: do we need the One-To-One map ..?
                classinfo.vtable_ea = vtable_ea
                classinfo.vtable_end_ea = vtable_end_ea


            elif len(candidates) > 1:
                candidates_str = ', '.join(hex(x) for x in candidates)
                self.log.warning(f'{classinfo.classname} {getmetaclass_ea:#x} has multiple vtable candidates {candidates_str}')
            else:
                self.log.error(f'No potential vtable xref to {classinfo.classname}::getMetaClass found!')
