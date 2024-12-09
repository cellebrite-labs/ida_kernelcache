"""
Useful references:

- https://developer.apple.com/documentation/kernel/osmetaclassbase
- https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/WritingDeviceDriver/CPluPlusRuntime/CPlusPlusRuntime.html
"""
import collections
import re

import idc
import idautils
import ida_xref
import ida_hexrays

from .base_phase import BasePhase
from ida_kernelcache import class_info, symbol
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.utils import OneToOneMapFactory

import ida_kernelcache.ida_helpers.decompiler as decompiler
import ida_kernelcache.ida_helpers.names as names
import ida_kernelcache.ida_helpers as ida_helpers
from ..consts import OSMETACLASS_CTOR_SYMBOL


class CollectClasses(BasePhase):
    """
    Collect information about C++ classes defined in a kernelcache. Arm64 only.

    This function searches through an iOS kernelcache for information about the C++ classes defined
    in it. It populates the global class_info dictionary, which maps the C++ class names to a
    ClassInfo object containing metainformation about the class.

    To force re-evaluation of the class_info dictionary, call class_info.clear() and then re-run
    this function.

    This function also collects the set of all virtual method tables identified in the kernelcache,
    even if the corresponding class could not be identified. A mapping from each virtual method
    table to its length is stored in the global vtables variable.

    Only Arm64 is supported at this time.

    TODO: An example to a nested class that is interesting and we are missing ..?
    Only top-level classes are processed. Information about nested classes is not collected.
    """

    NUM_EXPECTED_ARGS = 4

    def __init__(self, kc):
        super().__init__(kc)

        self.osmetaclass_constructor_ea: int
        # Collect associations from class names to metaclass instances and vice versa.

        self._metaclass_to_classname_builder = OneToOneMapFactory()
        self._metaclass_to_class_size = {}
        self._metaclass_to_super_metaclass = {}
        self._visited: set[int] = set()
        self._var_expr_errors = collections.defaultdict(set)

        # Statistics
        self._num_xrefs = 0
        self._num_failed = 0
        self._num_succeeded = 0
        self._num_duplicates = 0
        self._num_unique_unresolved = 0

    def run(self):
        # Clear out old class information
        self._kc.class_info_map.clear()
        self._find_osmetaclass_constructor()
        self._collect_metaclasses()

        # Filter out any class name (and its associated metaclasses) that has multiple metaclasses.
        # This can happen when multiple kexts define a class but only one gets loaded.
        def bad_classname(classname, metaclasses):
            self.log.warning(f'Class {classname} has multiple metaclasses: {", ".join(["{:#x}".format(mc) for mc in metaclasses])}')

        # Filter out any metaclass (and its associated class names) that has multiple class names. I
        # have no idea why this would happen.
        def bad_metaclass(metaclass, classnames):
            self.log.warning(f'Metaclass {metaclass:#x} has multiple classes: {", ".join(classnames)}')

        # Return the final dictionary of metaclass info.
        metaclass_to_classname = self._metaclass_to_classname_builder.build(bad_metaclass, bad_classname)
        for metaclass_ea, classname in metaclass_to_classname.items():
            meta_superclass = self._metaclass_to_super_metaclass[metaclass_ea]
            superclass_name = metaclass_to_classname.get(meta_superclass, None)
            info = class_info.ClassInfo(classname,
                                        metaclass_ea,
                                        self._metaclass_to_class_size[metaclass_ea],
                                        superclass_name,
                                        meta_superclass)
            self._kc.class_info_map.add_classinfo(info)

        for classname_str, errors_ea_set in self._var_expr_errors.items():
            if classname_str in self._kc.class_info_map:
                # Don't consider those as failures in the statistics because we got the class info from somewhere else
                self._num_failed -= len(errors_ea_set)
                self._num_duplicates += len(errors_ea_set)
            else:
                self.log.error(f'Unresolved {classname_str}: {", ".join(f"{ea:#x}" for ea in errors_ea_set)}')
                self._num_unique_unresolved += 1

        # Print statistics
        self.log.info(f'\n\ttotal:{self._num_xrefs} xrefs in {len(self._visited)} unique functions\n\t'
                      f'succeeded:{self._num_succeeded}\n\t'
                      f'failed:{self._num_failed} xrefs, a total of {self._num_unique_unresolved} unresolved classes\n\t'
                      f'duplicates:{self._num_duplicates}\n\t')

    def _find_osmetaclass_constructor(self):
        """
        Locate OSMetaClass::OSMetaClass function. We do this by finding the first reference to the OSObject string
        """
        try:
            OSObject_str = next(s for s in idautils.Strings() if str(s) == "OSObject")
        except StopIteration:
            raise PhaseException("Couldn't find OSObject str")

        # Surprisingly this hack works.. the first dref is the OSMetaClass::OSMetaClass constructor we are looking for
        OSObject_xref = ida_xref.get_first_dref_to(OSObject_str.ea)

        # Decompile the method using hexrays
        cfunc = ida_hexrays.decompile(OSObject_xref)
        if cfunc is None:
            raise PhaseException("hexrays decompilation failed! did IDA finish processing the kernel yet?")

        visitor = decompiler.FindCallByArgVisitor(OSObject_str.ea)
        visitor.apply_to(cfunc.body, parent=None)

        if not visitor.found:
            raise PhaseException("Failed to find OSMetaclass::OSMetaclass ea!")

        self.osmetaclass_constructor_ea = visitor.func_ea
        self.log.info(f'Found OSMetaClass::OSMetaClass {self.osmetaclass_constructor_ea:#x}')
        names.set_ea_name(self.osmetaclass_constructor_ea, OSMETACLASS_CTOR_SYMBOL)

    def _find_osmetaclass_constructor_with_zone(self):
        try:
            IOSurface_str = next(s for s in idautils.Strings() if str(s) == "IOSurface")
        except StopIteration:
            raise PhaseException("Couldn't find OSObject str")

        visitor = decompiler.FindCallByArgVisitor(IOSurface_str.ea)

        for xref_ea in idautils.DataRefsTo(IOSurface_str.ea):
            func_start_ea = ida_helpers.get_func_start(xref_ea)

            # Decompile the method using hexrays
            cfunc = ida_hexrays.decompile(func_start_ea)
            if cfunc is None:
                raise PhaseException("hexrays decompilation failed! did IDA finish processing the kernel yet?")
            visitor.apply_to(cfunc.body, parent=None)

        if not visitor.found:
            raise PhaseException("Failed to find OSMetaclass::OSMetaclass ea!")

        self.osmetaclass_constructor_ea = visitor.func_ea
        self.log.info(f'Found OSMetaClass::OSMetaClass {self.osmetaclass_constructor_ea:#x}')
        names.set_ea_name(self.osmetaclass_constructor_ea, OSMETACLASS_CTOR_SYMBOL)

    def _collect_metaclasses(self):
        """
        Collect OSMetaClass information from all kexts in the kernelcache.
        """
        old = idc.batch(1)

        try:
            # There are ~300 data refs in __auth_got segments however they do not seem to be used at all so I intentionally
            # choose to skip them.
            for xref_ea in idautils.CodeRefsTo(self.osmetaclass_constructor_ea, flow=False):
                self._num_xrefs += 1
                func_start_ea = ida_helpers.get_func_start(xref_ea)
                self._visited.add(func_start_ea)
                if self._handle_callsite(xref_ea):
                    self._num_succeeded += 1
                else:
                    self._num_failed += 1

        finally:
            idc.batch(old)

    def _handle_callsite(self, ea: int, must_find_call: bool = True) -> bool:
        args_ops = [
            (ida_hexrays.cot_cast, ida_hexrays.cot_ref, ida_hexrays.cot_var),
            (ida_hexrays.cot_obj,),
            (ida_hexrays.cot_cast, ida_hexrays.cot_ref, ida_hexrays.cot_num),
            (ida_hexrays.cot_num,)
        ]

        visitor = decompiler.FindCallVisitor(self.osmetaclass_constructor_ea, ea, args_ops)
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            self.log.error(f'hexrays decompilation failed at {ea:#x}')
            return False

        visitor.apply_to(cfunc.body, parent=None)
        if not visitor.found:

            # don't spam error logs for mod_init functions that are not related to global objects
            if must_find_call:
                self.log.error(f'Failed to find OSMetaClass::OSMetaClass call site in the ctree {ea:#x}')
            return False

        if not visitor.passed_ops_validation:
            self.log.error(f'Failed ops validations! ops:[{", ".join(str(a.op) for a in visitor.args)}] {ea:#x}')
            return False

        # Make sure that the classname is within a cstring section and then read its contents
        classname_ea = visitor.args[1].obj_ea
        if not re.match(r".*__(cstring|const)$", idc.get_segm_name(classname_ea)):
            self.log.error(f'arg[1] does not belong in a __cstring/__const segment! ea:{ea:#x} classname_ea:{classname_ea:#x}')
            return False

        classname_str = idc.get_strlit_contents(classname_ea).decode()
        classname_str_clean = symbol.clean_templated_name(classname_str)
        metaclass_arg = decompiler.traverse_casts_or_ref_branch(visitor.args[0])
        match metaclass_arg.op:
            case ida_hexrays.cot_var:

                # Seems like there are a lot of useless constructors that are not used, we cannot find their corresponding
                # metaclass because it is passed as a variable instead of a reference.
                # Usually for those there will be some other valid xref to this classname. So the approach I took here is to
                # only inform the user of these errors after finishing collecting from all possible sources
                # Fail silently and only check later
                self._var_expr_errors[classname_str_clean].add(ea)
                return False
            case ida_hexrays.cot_obj:
                metaclass_ea = metaclass_arg.obj_ea
            case _:
                self.log.error(f'unexpected ctree structure arg[0] branch did not lead to cot_obj! ea:{ea:#x}')
                return False

        super_metaclass_arg = decompiler.traverse_casts_or_ref_branch(visitor.args[2])
        match super_metaclass_arg.op:
            case ida_hexrays.cot_num:
                if super_metaclass_arg.numval():
                    self.log.error(f'arg[2] is a non-zero numeric value! ea:{ea:#x}')
                    return False
                super_metaclass_ea = 0
            case ida_hexrays.cot_obj:
                super_metaclass_ea = super_metaclass_arg.obj_ea
            case _:
                self.log.error(f'unexpected ctree structure arg[0] branch did not lead to cot_obj! ea:{ea:#x}')
                return False

        # fourth argument is always cot_numval
        class_size = visitor.args[3].numval()

        # We found valid information. record it
        self.log.debug(f"Found metaclass info for {classname_str} at {ea:#x}")

        self._metaclass_to_classname_builder.add_link(metaclass_ea, classname_str_clean)
        self._metaclass_to_class_size[metaclass_ea] = class_size
        self._metaclass_to_super_metaclass[metaclass_ea] = super_metaclass_ea
        return True
