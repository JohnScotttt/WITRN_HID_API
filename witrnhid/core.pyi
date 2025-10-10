# Copyright (c) 2025 JohnScotttt
# Version pre 0.1.2

__version__ = "pre 0.1.3"

K2_TARGET_VID = 0x0716
K2_TARGET_PID = 0x5060


class metadata:
    def raw(): ...
    def bit_loc(): ...
    def field(): ...
    def value(): ...


class WITRN_DEV:
    """
    The default vid and pid are directly connected to K2 without the need for setting.

    Debug mode is enabled only when a large amount of 'Error Data' is detected. In this case, the API will raise an exception.
    """

    def __init__(self,
                 vid: int = K2_TARGET_VID,
                 pid: int = K2_TARGET_PID,
                 debug: bool = False): ...

    def read_data() -> list: ...
    def general_unpack(self, data: list = None) -> metadata: ...

    def pd_unpack(self,
                  data: list = None,
                  last_pdo: metadata = None,
                  last_ext: metadata = None,
                  last_rdo: metadata = None) -> metadata: ...

    def auto_unpack(self,
                    data: list = None,
                    last_pdo: metadata = None,
                    last_ext: metadata = None,
                    last_rdo: metadata = None) -> metadata: ...

    def close(self): ...
