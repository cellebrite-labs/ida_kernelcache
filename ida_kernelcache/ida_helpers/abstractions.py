import ida_segment


class Segment:
    """
    A more friendly wrapper around ida segments
    """

    def __init__(self, swig_segment: ida_segment.segment_t):
        self.name = ida_segment.get_segm_name(swig_segment)
        self.start_ea = swig_segment.start_ea
        self.end_ea = swig_segment.end_ea
        self.size = self.end_ea - self.start_ea
        self.seg_class = ida_segment.get_segm_class(swig_segment)

    def __repr__(self):
        return f'[{self.start_ea:#x}-{self.end_ea:#x}] {self.name} size:{self.size} cls:{self.seg_class}'
