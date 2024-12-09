from collections import defaultdict


def iterlen(iterator):
    """
    Consume an iterator and return its length.
    """
    return sum(1 for _ in iterator)


class OneToOneMapFactory(object):
    """A factory to extract the largest one-to-one submap."""

    def __init__(self):
        self._as_to_bs = defaultdict(set)
        self._bs_to_as = defaultdict(set)

    def add_link(self, a, b):
        """Add a link between the two objects."""
        self._as_to_bs[a].add(b)
        self._bs_to_as[b].add(a)

    def _make_unique_oneway(self, xs_to_ys, ys_to_xs, bad_x=None):
        """Internal helper to make one direction unique."""
        for x, ys in list(xs_to_ys.items()):
            if len(ys) != 1:
                if bad_x:
                    bad_x(x, ys)
                del xs_to_ys[x]
                for y in ys:
                    del ys_to_xs[y]

    def _build_oneway(self, xs_to_ys):
        """Build a one-way mapping after pruning."""
        x_to_y = dict()
        for x, ys in list(xs_to_ys.items()):
            x_to_y[x] = next(iter(ys))
        return x_to_y

    def build(self, bad_a=None, bad_b=None):
        """Extract the smallest one-to-one submap."""
        as_to_bs = dict(self._as_to_bs)
        bs_to_as = dict(self._bs_to_as)
        self._make_unique_oneway(as_to_bs, bs_to_as, bad_a)
        self._make_unique_oneway(bs_to_as, as_to_bs, bad_b)
        return self._build_oneway(as_to_bs)
