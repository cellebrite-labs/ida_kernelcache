# The size of a word on the current platform.
WORD_SIZE = 8

# The first few entries of the virtual method tables in the kernelcache are empty.
# TODO: Theoretically this can change (and therefore break) however it rarely happens
VTABLE_FIRST_METHOD_OFFSET = 2 * WORD_SIZE
VTABLE_GETMETACLASS_OFFSET = (2 + 7) * WORD_SIZE
INITIAL_NUM_VTABLE_METHODS = 7

OSMETACLASS_CTOR_SYMBOL = '__ZN11OSMetaClassC2EPKcPKS_j'