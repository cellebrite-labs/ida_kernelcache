"""
Register a new IDA Plugin using the python api.
See: https://hex-rays.com/blog/scriptable-plugins/ and loader.hpp in the IDA SDK
"""
import idaapi
from ida_kernelcache.kernelcache import KernelCache


class IDAKernelCachePlugin(idaapi.plugin_t):
    wanted_name = "IDA KernelCache"
    wanted_hotkey = "Meta-K"

    # TODO: add PLUGIN_MOD flag when this plugin is
    # TODO: add PLUGIN_HIDE when manually adding menu items..
    flags = 0
    comment = ""
    help = ""

    # TODO: add more menu items
    # See: https://hex-rays.com/blog/augmenting-ida-ui-with-your-own-actions/ and the Pacxplorer plugin by Lipner..
    def init(self):

        if not KernelCache.is_input_file_kernelcache():
            return idaapi.PLUGIN_SKIP

        print('[ida_kernelcache] init callback has been called..')
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # TODO: do we want to store this variable as an attribute of the plugin?
        kc = KernelCache()
        phases = kc.all_phases()
        kc.process(phases)

    def term(self):
        # TODO: cache data in the IDB for persistency?
        print('[ida_kernelcache] term callback has been called..')


def PLUGIN_ENTRY():
    print('[ida_kernelcache] Plugin loaded')
    return IDAKernelCachePlugin()
