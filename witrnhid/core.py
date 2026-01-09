# Copyright (c) 2025 JohnScotttt
# Version 1.1.4

from usbpdparser import Parser, metadata, is_pdo, is_rdo, provide_ext
from usbpdparser.tools import renderer
import struct
from datetime import timedelta, datetime
import hid

__version__ = "1.1.4"

K2_TARGET_VID = 0x0716
K2_TARGET_PID = 0x5060


def lst2str(lst: list, order: str = '<') -> str:
    if order == '>':
        return ''.join(f'{x:08b}' for x in bytes(lst))
    elif order == '<':
        return ''.join(f'{x:08b}' for x in bytes(lst)[::-1])
    else:
        raise ValueError("Order must be '>' or '<'")


class general_msg(metadata):
    def __init__(self, data: list):
        super().__init__(bit_loc=(0, 511), field="general")
        self._raw = lst2str(data, '>')
        self._value = [
            metadata(lst2str(data[14:18]), (112, 143), "Ah",
                     f"{struct.unpack('<f', bytes(data[14:18]))[0]}Ah"),
            metadata(lst2str(data[18:22]), (144, 175), "Wh",
                     f"{struct.unpack('<f', bytes(data[18:22]))[0]}Wh"),
            metadata(lst2str(data[22:26]), (176, 207), "Rectime",
                     str(timedelta(seconds=struct.unpack('<I', bytes(data[22:26]))[0]))),
            metadata(lst2str(data[26:30]), (208, 239), "Runtime",
                     str(timedelta(seconds=struct.unpack('<I', bytes(data[26:30]))[0]))),
            metadata(lst2str(data[30:34]), (240, 271), "D+",
                     f"{struct.unpack('<f', bytes(data[30:34]))[0]}V"),
            metadata(lst2str(data[34:38]), (272, 303), "D-",
                     f"{struct.unpack('<f', bytes(data[34:38]))[0]}V"),
            metadata(lst2str(data[42:46]), (336, 367), "Temperature",
                     f"{struct.unpack('<f', bytes(data[42:46]))[0]}°C"),
            metadata(lst2str(data[46:50]), (368, 399), "VBus",
                     f"{struct.unpack('<f', bytes(data[46:50]))[0]}V"),
            metadata(lst2str(data[50:54]), (400, 431), "Current",
                     f"{struct.unpack('<f', bytes(data[50:54]))[0]}A"),
            metadata(lst2str([data[54:55]][0]), (432, 439), "Group", f"{data[54] + 1}"),
            metadata(lst2str([data[55:56]][0]), (440, 447), "CC1", f"{data[55] / 10}V"),
            metadata(lst2str([data[56:57]][0]), (448, 455), "CC2", f"{data[56] / 10}V"),
        ]


class WITRN_DEV(Parser):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.data = None
        self.timestamp = None

    def open(self, *args, **kwargs):
        vid = pid = path = None
        if args == () and kwargs == {}:
            vid = K2_TARGET_VID
            pid = K2_TARGET_PID
        elif args != () and kwargs == {}:
            if len(args) == 1 and isinstance(args[0], bytes):
                path = args[0]
            elif len(args) == 2 and all(isinstance(i, int) for i in args):
                vid = args[0]
                pid = args[1]
            else:
                raise ValueError("Invalid arguments")
        elif args == () and kwargs != {}:
            if "vid" in kwargs and "pid" in kwargs:
                if "path" not in kwargs:
                    vid = kwargs["vid"]
                    pid = kwargs["pid"]
                else:
                    raise ValueError("Cannot specify both (vid, pid) and path")
            else:
                if "path" in kwargs:
                    path = kwargs["path"]
                else:
                    raise ValueError("Must specify either (vid, pid) or path")
        else:
            raise ValueError("Cannot mix positional and keyword arguments")

        self.dev = hid.device()
        if path is None:
            self.dev.open(vid, pid)
        else:
            self.dev.open_path(path)
    
    def read_data(self) -> list:
        self.data = self.dev.read(64)
        self.timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        return self.data
    
    def general_unpack(self, data: list = None) -> tuple[str, metadata]:
        if data is None:
            if self.data is None:
                raise ValueError("No data available to unpack")
            elif len(self.data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            return self.timestamp, general_msg(self.data)
        else:
            if len(data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            return timestamp, general_msg(data)
        
    def pd_unpack(self,
                  data: list = None,
                  last_pdo: metadata = None,
                  last_ext: metadata = None,
                  last_rdo: metadata = None) -> tuple[str, metadata]:
        SOP = {
            224: "SOP",
            192: "SOP'",
            160: "SOP''",
            128: "SOP'_DEBUG",
            96: "SOP''_DEBUG",
        }
        if data is None:
            if self.data is None:
                raise ValueError("No data available to unpack")
            elif len(self.data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            sop = SOP.get(self.data[2], "SOP")
            end_of_msg = self.data[1] + 2
            msg = super().parse(sop=sop,
                                raw=self.data[3:end_of_msg],
                                verify_crc=False,
                                prop_protocol=True)
            return self.timestamp, msg
        else:
            if len(data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            sop = SOP.get(data[2], "SOP")
            end_of_msg = data[1] + 2
            msg = super().parse(sop=sop,
                                raw=data[3:end_of_msg],
                                verify_crc=False,
                                prop_protocol=True,
                                last_pdo=last_pdo,
                                last_ext=last_ext,
                                last_rdo=last_rdo)
            return timestamp, msg
        
    def auto_unpack(self,
                    data: list = None,
                    last_pdo: metadata = None,
                    last_ext: metadata = None,
                    last_rdo: metadata = None) -> tuple[str, metadata]:
        if data is None:
            if self.data is None:
                raise ValueError("No data available to unpack")
            elif len(self.data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            if self.data[0] == 255:
                return self.general_unpack()
            elif self.data[0] == 254:
                return self.pd_unpack()
        else:
            if len(data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            if data[0] == 255:
                return self.general_unpack(data)
            elif data[0] == 254:
                return self.pd_unpack(data, last_pdo, last_ext, last_rdo)

    def close(self):
        self.dev.close()