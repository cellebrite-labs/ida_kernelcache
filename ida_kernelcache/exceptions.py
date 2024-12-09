class PhaseException(Exception):
    pass


class AlignmentError(Exception):
    """
    An exception that is thrown if an address with improper alignment is encountered.
    """

    def __init__(self, address):
        self.address = address

    def __str__(self):
        return repr(self.address)


class InvalidKeyTypeError(PhaseException):
    """
    May be used to indicate that a key is not
    """
    pass
