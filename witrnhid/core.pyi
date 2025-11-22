# Copyright (c) 2025 JohnScotttt
# Version 1.0.3

__version__ = "1.0.3"

K2_TARGET_VID = 0x0716
K2_TARGET_PID = 0x5060


class metadata:
    def raw():
        """Return raw binary string representation of the field.""" 
        ...
    def bit_loc():
        """Return tuple of (start_bit, end_bit) for the field."""
        ...
    def field():
        """Return the name of the field."""
        ...
    def value():
        """Return the value of the field."""
        ...
    def quick_pdo(self) -> str:
        """Return a quick description if the field is a PDO."""
        ...
    def quick_rdo(self) -> str:
        """Return a quick description if the field is an RDO."""
        ...
    def pdo(self) -> metadata:
        """Return the PDO metadata form RDO if applicable."""
        ...
    def full_raw(self) -> str:
        """Return full raw binary string of the extended message."""
        ...
    def raw_value(self):
        """Return the raw value of the extended message."""
        ...


class WITRN_DEV:
    def __init__(self, **kwargs): ...

    def open(self, *args, **kwargs): ...

    def read_data() -> list: ...

    def general_unpack(self, data: list = None) -> tuple[str, metadata]: ...

    def pd_unpack(self,
                  data: list = None,
                  last_pdo: metadata = None,
                  last_ext: metadata = None,
                  last_rdo: metadata = None) -> tuple[str, metadata]: ...

    def auto_unpack(self,
                    data: list = None,
                    last_pdo: metadata = None,
                    last_ext: metadata = None,
                    last_rdo: metadata = None) -> tuple[str, metadata]: ...

    def close(self): ...


def is_pdo(msg: metadata) -> bool: ...

def is_rdo(msg: metadata) -> bool: ...

def provide_ext(msg: metadata) -> bool: ...
