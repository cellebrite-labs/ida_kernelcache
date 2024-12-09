"""
This is a stub file to be dropped in IDA plugins directory (usually ~/.idapro/plugins)
You should install ida_kernelcache package globally in your python installation (When developing, use an editable install..)
Make sure that this is the python version that IDA is using (otherwise you can switch with idapyswitch..)
Then copy ida_plugin_stub.py to ~/idapro/plugins/ida_kernelcache.py
"""
try:
    from ida_kernelcache.ida_plugin import PLUGIN_ENTRY, IDAKernelCachePlugin
except ImportError:
    print("[ida_kernelcache] Could not load IDA KernelCAche plugin. ida_kernelcache Python package doesn't seem to be installed.")
