
class ProtocolError(Exception):
    pass


class UnknownClient(ProtocolError):
    pass
