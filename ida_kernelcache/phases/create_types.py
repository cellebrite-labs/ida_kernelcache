# Standard library
from typing import Deque, TYPE_CHECKING
from collections import deque

# IDA
import ida_typeinf

# Project specific
from .base_phase import BasePhase
from ida_kernelcache.exceptions import PhaseException

if TYPE_CHECKING:
    from ida_kernelcache.class_info import ClassInfo

TYPE_DECL_NO_SUPERCLASS_TEMPLATE = '''\
struct __cppobj {class_name} {

};'''

TYPE_DECL_TEMPLATE = '''\
struct __cppobj {class_name} : {superclass_name} {
    
};'''


class CreateTypes(BasePhase):
    """
    Using the classes and vtables data from previous phases, the CreateTypes phase will define local types in the IDB.
    The struct definitions should represent the inheritance relationship between the classes
    This phase was improved to support the c++ objects support that was added in IDA 7.2, in particular the __cppobj
    attribute and the special _vtbl_layout suffix.


    In IDA a cpp structure has the TAUDT_CPPOBJ flag set in its udt_type_data_t object.
    Inheritance is achieved through a special member which is udm_t that is marked as baseclass at offset 0
    """

    def __init__(self, kc):
        super().__init__(kc)

    def verify_no_overrides(self):

        # TODO: I want to detect if an existing type already named X exists in the IDB and if so.. prompt the user to make a decision how to proceed
        pass

    def run(self):

        queue: Deque[ClassInfo] = deque((ci for ci in self._kc.classes if ci.superclass is None))

        if not queue:
            pass
        # Do a breadth first scan, the inheritance relationship forms a directed acylic graph so there is no need
        # to track down visited nodes

        while queue:
            class_info = queue.popleft()

            if class_info.superclass:
                type_declaration = f'struct __cppobj {class_info.classname} : {class_info.superclass_name} {{ }};'
            else:
                type_declaration = f'struct __cppobj {class_info.classname} {{ }};'

            ida_typeinf.idc_parse_types(type_declaration)

            for subclass in class_info.subclasses:
                queue.append(subclass)
