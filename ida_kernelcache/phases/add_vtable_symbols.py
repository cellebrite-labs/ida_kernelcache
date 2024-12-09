from .base_phase import BasePhase
import ida_kernelcache.ida_utilities as idau
from ida_kernelcache.symbol import vtable_symbol_for_class


class AddVtableSymbols(BasePhase):
    """
    Populate IDA with virtual method table symbols for an iOS kernelcache.
    TODO: this is still a work in progress!
    """

    def run(self):
        for class_name, class_info in self._kc.classes.items():
            if class_info.vtable:
                if class_info.superclass_name and self._kc.classes[class_info.superclass_name].vtable == class_info.vtable:
                    self.log(3, 'Class {} has the same vtable as its parent {} at: {:#x}', class_name, class_info.superclass_name, class_info.vtable)
                    continue

                self.log(3, 'Class {} has vtable at {:#x}', class_name, class_info.vtable)
                if not self._add_vtable_symbol(class_info.vtable, class_name):
                    self.log(0, 'Could not add vtable symbol for class {} at address {:#x}', class_name, class_info.vtable)
            else:
                self.log(0, 'Class {} has no known vtable', class_name)

    def _add_vtable_symbol(self, vtable, class_name):
        """
        Add a symbol for the virtual method table at the specified address.

        Arguments:
            vtable: The address of the virtual method table.
            class_name: The name of the C++ class with this virtual method table.

        Returns:
            True if the data was successfully converted into a vtable and the symbol was added.
        """
        vtable_symbol = vtable_symbol_for_class(class_name)
        if not idau.set_ea_name(vtable, vtable_symbol, rename=True):
            self.log(0, 'Address {:#x} already has name {} instead of vtable symbol {}'
                     .format(vtable, idau.get_ea_name(vtable), vtable_symbol))
            return False
        return True
