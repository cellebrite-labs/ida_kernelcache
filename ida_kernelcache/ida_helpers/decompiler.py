"""
//-------------------------------------------------------------------------
/// Ctree item code. At the beginning of this list there are expression
/// codes (cot_...), followed by statement codes (cit_...).
enum ctype_t
{
  cot_empty    = 0,
  cot_comma    = 1,   ///< x, y
  cot_asg      = 2,   ///< x = y
  cot_asgbor   = 3,   ///< x |= y
  cot_asgxor   = 4,   ///< x ^= y
  cot_asgband  = 5,   ///< x &= y
  cot_asgadd   = 6,   ///< x += y
  cot_asgsub   = 7,   ///< x -= y
  cot_asgmul   = 8,   ///< x *= y
  cot_asgsshr  = 9,   ///< x >>= y signed
  cot_asgushr  = 10,  ///< x >>= y unsigned
  cot_asgshl   = 11,  ///< x <<= y
  cot_asgsdiv  = 12,  ///< x /= y signed
  cot_asgudiv  = 13,  ///< x /= y unsigned
  cot_asgsmod  = 14,  ///< x %= y signed
  cot_asgumod  = 15,  ///< x %= y unsigned
  cot_tern     = 16,  ///< x ? y : z
  cot_lor      = 17,  ///< x || y
  cot_land     = 18,  ///< x && y
  cot_bor      = 19,  ///< x | y
  cot_xor      = 20,  ///< x ^ y
  cot_band     = 21,  ///< x & y
  cot_eq       = 22,  ///< x == y int or fpu (see EXFL_FPOP)
  cot_ne       = 23,  ///< x != y int or fpu (see EXFL_FPOP)
  cot_sge      = 24,  ///< x >= y signed or fpu (see EXFL_FPOP)
  cot_uge      = 25,  ///< x >= y unsigned
  cot_sle      = 26,  ///< x <= y signed or fpu (see EXFL_FPOP)
  cot_ule      = 27,  ///< x <= y unsigned
  cot_sgt      = 28,  ///< x >  y signed or fpu (see EXFL_FPOP)
  cot_ugt      = 29,  ///< x >  y unsigned
  cot_slt      = 30,  ///< x <  y signed or fpu (see EXFL_FPOP)
  cot_ult      = 31,  ///< x <  y unsigned
  cot_sshr     = 32,  ///< x >> y signed
  cot_ushr     = 33,  ///< x >> y unsigned
  cot_shl      = 34,  ///< x << y
  cot_add      = 35,  ///< x + y
  cot_sub      = 36,  ///< x - y
  cot_mul      = 37,  ///< x * y
  cot_sdiv     = 38,  ///< x / y signed
  cot_udiv     = 39,  ///< x / y unsigned
  cot_smod     = 40,  ///< x % y signed
  cot_umod     = 41,  ///< x % y unsigned
  cot_fadd     = 42,  ///< x + y fp
  cot_fsub     = 43,  ///< x - y fp
  cot_fmul     = 44,  ///< x * y fp
  cot_fdiv     = 45,  ///< x / y fp
  cot_fneg     = 46,  ///< -x fp
  cot_neg      = 47,  ///< -x
  cot_cast     = 48,  ///< (type)x
  cot_lnot     = 49,  ///< !x
  cot_bnot     = 50,  ///< ~x
  cot_ptr      = 51,  ///< *x, access size in 'ptrsize'
  cot_ref      = 52,  ///< &x
  cot_postinc  = 53,  ///< x++
  cot_postdec  = 54,  ///< x--
  cot_preinc   = 55,  ///< ++x
  cot_predec   = 56,  ///< --x
  cot_call     = 57,  ///< x(...)
  cot_idx      = 58,  ///< x[y]
  cot_memref   = 59,  ///< x.m
  cot_memptr   = 60,  ///< x->m, access size in 'ptrsize'
  cot_num      = 61,  ///< n
  cot_fnum     = 62,  ///< fpc
  cot_str      = 63,  ///< string constant (user representation)
  cot_obj      = 64,  ///< obj_ea
  cot_var      = 65,  ///< v
  cot_insn     = 66,  ///< instruction in expression, internal representation only
  cot_sizeof   = 67,  ///< sizeof(x)
  cot_helper   = 68,  ///< arbitrary name
  cot_type     = 69,  ///< arbitrary type
  cot_last     = cot_type,
  cit_empty    = 70,  ///< instruction types start here
  cit_block    = 71,  ///< block-statement: { ... }
  cit_expr     = 72,  ///< expression-statement: expr;
  cit_if       = 73,  ///< if-statement
  cit_for      = 74,  ///< for-statement
  cit_while    = 75,  ///< while-statement
  cit_do       = 76,  ///< do-statement
  cit_switch   = 77,  ///< switch-statement
  cit_break    = 78,  ///< break-statement
  cit_continue = 79,  ///< continue-statement
  cit_return   = 80,  ///< return-statement
  cit_goto     = 81,  ///< goto-statement
  cit_asm      = 82,  ///< asm-statement
  cit_end
};
"""
import logging
import ida_hexrays
import idc

from . import read_ptr


class FindCallByArgVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, target_arg_ea: int):
        self._target_arg_ea = target_arg_ea
        self.found: bool = False
        self.func_ea: int = idc.BADADDR
        super().__init__(ida_hexrays.CV_PARENTS)

    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        parent: ida_hexrays.cexpr_t = self.parent_expr()
        if (expr.op == ida_hexrays.cot_obj and
                expr.obj_ea == self._target_arg_ea and
                parent.op == ida_hexrays.cot_call and
                parent.x.op == ida_hexrays.cot_obj):
            self.found = True
            self.func_ea = parent.x.obj_ea
            return 1
        return 0


class FindCallVisitor(ida_hexrays.ctree_visitor_t):

    def __init__(self, target_func_ea: int, cot_expr_ea: int, args_ops: list[tuple[int, ...] | None]):
        self._target_func_ea = target_func_ea
        self._xref_ea = cot_expr_ea
        self._args_ops = args_ops

        self.found: bool = False
        self.passed_ops_validation: bool = False
        self.args: ida_hexrays.carglist_t | None = None
        super().__init__(ida_hexrays.CV_FAST)

    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        # Filter
        if (expr.op == ida_hexrays.cot_call and  # This is a call expression
                expr.ea == self._xref_ea and  # This is the xref we are looking for
                expr.x.op == ida_hexrays.cot_obj and  # This is a call to the function we are looking for
                expr.x.obj_ea == self._target_func_ea and
                len(expr.a) == len(self._args_ops)):  # The number of args in this call are the expected number of args
            self.found = True
            self.args = expr.a

            # For every argument we make sure that its op is in the whitelist ops
            for arg, ops in zip(expr.a, self._args_ops):
                if ops is None:
                    continue
                if arg.op not in ops:
                    return 1

            self.passed_ops_validation = True
            return 1

        # Continue the search
        return 0


def traverse_casts_or_ref_branch(expr: ida_hexrays.cexpr_t) -> ida_hexrays.cexpr_t:
    # TODO: what happens (if it is even possible) that a leaf is cot_cast or cot_ref?
    while expr.op in [ida_hexrays.cot_cast, ida_hexrays.cot_ref]:
        expr = expr.x
    return expr

    # if expr.op != ida_hexrays.cot_obj:
    #     return None
    # if not found_ref and dref_obj:
    #     print('*'*50 + 'DREF OBJ!')
    #     return read_ptr(expr.obj_ea)
    # return expr.obj_ea
