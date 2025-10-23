# Start of File
# Copyright (c) 2025 JohnScotttt
# Version pre 0.3.7

import hid
import struct
from datetime import timedelta, datetime

__version__ = "pre 0.3.7"
__flag__ = False


K2_TARGET_VID = 0x0716
K2_TARGET_PID = 0x5060


def lst2str(lst: list, order: str = '<') -> str:
    if order == '>':
        return ''.join(f'{x:08b}' for x in bytes(lst))
    elif order == '<':
        return ''.join(f'{x:08b}' for x in bytes(lst)[::-1])
    else:
        raise ValueError("Order must be '>' or '<'")


class metadata:
    def __init__(self, raw: str = None, bit_loc: tuple = None, field: str = None, value=None):
        self._raw = raw
        self._bit_loc = bit_loc
        self._field = field
        self._value = value
    
    def raw(self) -> str:
        return self._raw
    
    def bit_loc(self) -> tuple:
        return self._bit_loc
    
    def field(self) -> str:
        return self._field
    
    def value(self):
        return self._value

    def __str__(self) -> str:
        return f"{self._value}"
    
    def __repr__(self) -> str:
        return f"{self._field}: {self._value}"
    
    def __getitem__(self, field):
        if isinstance(self._value, list):
            if not hasattr(self, 'field_map'):
                self._field_map = {m.field(): m for m in self._value}
                if "Reserved" in self._field_map:
                    del self._field_map["Reserved"]
            if isinstance(field, str):
                return self._field_map.get(field, None)
            else:
                return self._value[field]
        else:
            return "Not a list"
        
    def quick_pdo(self) -> str:
        return "Not a PDO"
    
    def quick_rdo(self) -> str:
        return "Not a RDO"
    
    def pdo(self) -> "metadata":
        return None
    
    def full_raw(self) -> str:
        return self._raw

    def raw_value(self):
        return self._value


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


class msg_header(metadata):
    def __init__(self, raw: str, bit_loc: tuple, sop: str):
        super().__init__(raw, bit_loc, "Message Header")

        CMT = {
            "00001": "GoodCRC",
            "00010": "GotoMin",
            "00011": "Accept",
            "00100": "Reject",
            "00101": "Ping",
            "00110": "PS_RDY",
            "00111": "Get_Source_Cap",
            "01000": "Get_Sink_Cap",
            "01001": "DR_Swap",
            "01010": "PR_Swap",
            "01011": "VCONN_Swap",
            "01100": "Wait",
            "01101": "Soft_Reset",
            "01110": "Data_Reset",
            "01111": "Data_Reset_Complete",
            "10000": "Not_Supported",
            "10001": "Get_Source_Cap_Extended",
            "10010": "Get_Status",
            "10011": "FR_Swap",
            "10100": "Get_PPS_Status",
            "10101": "Get_Country_Codes",
            "10110": "Get_Sink_Cap_Extended",
            "10111": "Get_Source_Info",
            "11000": "Get_Revision",
        }

        DMT = {
            "00001": "Source_Capabilities",
            "00010": "Request",
            "00011": "BIST",
            "00100": "Sink_Capabilities",
            "00101": "Battery_Status",
            "00110": "Alert",
            "00111": "Get_Country_Info",
            "01000": "Enter_USB",
            "01001": "EPR_Request",
            "01010": "EPR_Mode",
            "01011": "Source_Info",
            "01100": "Revision",
            "01111": "Vendor_Defined",
        }

        EMT = {
            "00001": "Source_Capabilities_Extended",
            "00010": "Status",
            "00011": "Get_Battery_Cap",
            "00100": "Get_Battery_Status",
            "00101": "Battery_Capabilities",
            "00110": "Get_Manufacturer_Info",
            "00111": "Manufacturer_Info",
            "01000": "Security_Request",
            "01001": "Security_Response",
            "01010": "Firmware_Update_Request",
            "01011": "Firmware_Update_Response",
            "01100": "PPS_Status",
            "01101": "Country_Info",
            "01110": "Country_Codes",
            "01111": "Sink_Capabilities_Extended",
            "10000": "Extended_Control",
            "10001": "EPR_Source_Capabilities",
            "10010": "EPR_Sink_Capabilities",
            "11110": "Vendor_Defined_Extended",
        }

        REV = {
            "00": "Rev 1.0",
            "01": "Rev 2.0",
            "10": "Rev 3.x",
        }

        self._value = [
            metadata(raw[0:1], (15, 15), "Extended", bool(int(raw[0:1]))),
            metadata(raw[1:4], (14, 12), "Number of Data Objects", int(raw[1:4], 2)),
            metadata(raw[4:7], (11, 9), "MessageID", int(raw[4:7], 2)),
        ]

        if sop == "SOP":
            self._value.append(metadata(raw[7:8], (8, 8), "Port Power Role",
                                        "Sink" if raw[7:8] == '0' else "Source"))
        elif sop in ["SOP'", "SOP''"]:
            self._value.append(metadata(raw[7:8], (8, 8), "Cable Plug",
                                        "DFP or UFP" if raw[7:8] == '0' else "Cable Plug or VPD"))
        else:
            self._value.append(metadata(raw[7:8], (8, 8), "Cable Plug",
                                        "DFP or UFP (D)" if raw[7:8] == '0' else "Cable Plug or VPD (D)"))

        self._value.append(metadata(raw[8:10], (7, 6), "Specification Revision", REV.get(raw[8:10], "Reserved")))

        if sop == "SOP":
            self._value.append(metadata(raw[10:11], (5, 5), "Port Data Role",
                                        "UFP" if raw[10:11] == '0' else "DFP"))
        else:
            self._value.append(metadata(raw[10:11], (5, 5), "Reserved"))
        
        if self._value[0].value():
            self._value.append(metadata(raw[11:16], (4, 0), "Message Type",
                                        EMT.get(raw[11:16], "Reserved")))
        else:
            if self._value[1].value() == 0:
                self._value.append(metadata(raw[11:16], (4, 0), "Message Type",
                                            CMT.get(raw[11:16], "Reserved")))
            else:
                self._value.append(metadata(raw[11:16], (4, 0), "Message Type",
                                            DMT.get(raw[11:16], "Reserved")))


def is_pdo(msg: metadata) -> bool:
    if msg["Message Header"] is None:
        return False
    msg_type = msg["Message Header"]["Message Type"].value()
    return msg_type in ["Source_Capabilities", "EPR_Source_Capabilities"]

def is_rdo(msg: metadata) -> bool:
    if msg["Message Header"] is None:
        return False
    msg_type = msg["Message Header"]["Message Type"].value()
    return msg_type in ["Request", "EPR_Request"]


class ex_msg_header(metadata):
    def __init__(self, raw: str, bit_loc: tuple):
        super().__init__(raw, bit_loc, "Extended Message Header")
        self._value = [
            metadata(raw[0:1], (15, 15), "Chunked", bool(int(raw[0:1]))),
            metadata(raw[1:5], (14, 11), "Chunk Number", int(raw[1:5], 2)),
            metadata(raw[5:6], (10, 10), "Request Chunk", bool(int(raw[5:6]))),
            metadata(raw[6:7], (9, 9), "Reserved"),
            metadata(raw[7:16], (8, 0), "Data Size", int(raw[7:16], 2)),
        ]


class VDM_header(metadata):
    def __init__(self, raw: str, bit_loc: tuple, **kwargs):
        super().__init__(raw, bit_loc, "VDM Header")

        VDM_Ver = {
            "0000": "Version 1.0",
            "0100": "Version 2.0",
            "0101": "Version 2.1",
        }

        Command_Type = {
            "00": "REQ",
            "01": "ACK",
            "10": "NAK",
            "11": "BUSY",
        }

        Command = {
            1: "Discover Identity",
            2: "Discover SVIDs",
            3: "Discover Modes",
            4: "Enter Mode",
            5: "Exit Mode",
            6: "Attention",
            **{i: "Reserved" for i in range(7, 16)},
        }

        if bool(int(raw[16:17])):
            self._value = [
                metadata(raw[0:16], (31, 16), "SVID", f"0x{int(raw[0:16], 2):04X}"),
                metadata(raw[16:17], (15, 15), "VDM Type", "Structured"),
                metadata(raw[17:21], (14, 11), "Structured VDM Version", VDM_Ver.get(raw[17:21], "Reserved")),
                metadata(raw[21:24], (10, 8), "Object Position", int(raw[21:24], 2)),
                metadata(raw[24:26], (7, 6), "Command Type", Command_Type.get(raw[24:26], "Reserved")),
                metadata(raw[26:27], (5, 5), "Reserved"),
                metadata(raw[27:32], (4, 0), "Command", Command.get(int(raw[27:32], 2), int(raw[27:32], 2)))
            ]
        else:
            self._value = [
                metadata(raw[0:16], (31, 16), "VID", f"0x{int(raw[0:16], 2):04X}"),
                metadata(raw[16:17], (15, 15), "VDM Type", "Unstructured"),
                metadata(raw[17:32], (14, 0), "Vendor Defined", f"0x{int(raw[17:32], 2):04X}")
            ]


class FPDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "FPDO"),
            metadata(raw[2:3], (29, 29), "Dual-Role Power", bool(int(raw[2:3]))),
            metadata(raw[3:4], (28, 28), "USB Suspend Supported", bool(int(raw[3:4]))),
            metadata(raw[4:5], (27, 27), "Unconstrained Power", bool(int(raw[4:5]))),
            metadata(raw[5:6], (26, 26), "USB Communications Capable", bool(int(raw[5:6]))),
            metadata(raw[6:7], (25, 25), "Dual-Role Data", bool(int(raw[6:7]))),
            metadata(raw[7:8], (24, 24), "Unchunked Extended Messages Supported", bool(int(raw[7:8]))),
            metadata(raw[8:9], (23, 23), "EPR Capable", bool(int(raw[8:9]))),
            metadata(raw[9:10], (22, 22), "Reserved"),
            metadata(raw[10:12], (21, 20), "Peak Current", raw[10:12]),
            metadata(raw[12:22], (19, 10), "Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Maximum Current", f"{int(raw[22:32], 2) / 100}A")
        ]

        self._quick_pdo = f"F {int(raw[12:22], 2) / 20}V@{int(raw[22:32], 2) / 100}A"

    def quick_pdo(self) -> str:
        return self._quick_pdo


class FPDO_S(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)

        FRSR = {
            "00": "Not Supported",
            "01": "Default USB Port",
            "10": "1.5A@5V",
            "11": "3A@5V",
        }

        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "FPDO Sink"),
            metadata(raw[2:3], (29, 29), "Dual-Role Power", bool(int(raw[2:3]))),
            metadata(raw[3:4], (28, 28), "Higher Capability", bool(int(raw[3:4]))),
            metadata(raw[4:5], (27, 27), "Unconstrained Power", bool(int(raw[4:5]))),
            metadata(raw[5:6], (26, 26), "USB Communications Capable", bool(int(raw[5:6]))),
            metadata(raw[6:7], (25, 25), "Dual-Role Data", bool(int(raw[6:7]))),
            metadata(raw[7:9], (24, 23), "Fast Role Swap required USB Type-C Current", FRSR.get(raw[7:9], "Reserved")),
            metadata(raw[9:12], (22, 20), "Reserved"),
            metadata(raw[12:22], (19, 10), "Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Operational Current", f"{int(raw[22:32], 2) / 100}A")
        ]


class BPDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "BPDO"),
            metadata(raw[2:12], (29, 20), "Maximum Voltage", f"{int(raw[2:12], 2) / 20}V"),
            metadata(raw[12:22], (19, 10), "Minimum Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Maximum Allowable Power", f"{int(raw[22:32], 2) / 4}W")
        ]

        self._quick_pdo = f"B {int(raw[12:22], 2) / 20}-{int(raw[2:12], 2) / 20}V@{int(raw[22:32], 2) / 4}W"

    def quick_pdo(self) -> str:
        return self._quick_pdo


class BPDO_S(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "BPDO Sink"),
            metadata(raw[2:12], (29, 20), "Maximum Voltage", f"{int(raw[2:12], 2) / 20}V"),
            metadata(raw[12:22], (19, 10), "Minimum Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Operational Power", f"{int(raw[22:32], 2) / 4}W")
        ]


class VPDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "VPDO"),
            metadata(raw[2:12], (29, 20), "Maximum Voltage", f"{int(raw[2:12], 2) / 20}V"),
            metadata(raw[12:22], (19, 10), "Minimum Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Maximum Current", f"{int(raw[22:32], 2) / 100}A")
        ]

        self._quick_pdo = f"V {int(raw[2:12], 2) / 20}-{int(raw[12:22], 2) / 20}V@{int(raw[22:32], 2) / 100}A"

    def quick_pdo(self) -> str:
        return self._quick_pdo


class VPDO_S(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "VPDO Sink"),
            metadata(raw[2:12], (29, 20), "Maximum Voltage", f"{int(raw[2:12], 2) / 20}V"),
            metadata(raw[12:22], (19, 10), "Minimum Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Operational Current", f"{int(raw[22:32], 2) / 100}A")
        ]


class PPS_PDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO"),
            metadata(raw[2:4], (29, 28), "APDO Type", "SPR PPS"),
            metadata(raw[4:5], (27, 27), "PPS Power Limited", bool(int(raw[4:5]))),
            metadata(raw[5:7], (26, 25), "Reserved"),
            metadata(raw[7:15], (24, 17), "Maximum Voltage", f"{int(raw[7:15], 2) / 10}V"),
            metadata(raw[15:16], (16, 16), "Reserved"),
            metadata(raw[16:24], (15, 8), "Minimum Voltage", f"{int(raw[16:24], 2) / 10}V"),
            metadata(raw[24:25], (7, 7), "Reserved"),
            metadata(raw[25:32], (6, 0), "Maximum Current", f"{int(raw[25:32], 2) / 20}A"),
        ]

        self._quick_pdo = f"P {int(raw[16:24], 2) / 10}-{int(raw[7:15], 2) / 10}V@{int(raw[25:32], 2) / 20}A"

    def quick_pdo(self) -> str:
        return self._quick_pdo


class PPS_PDO_S(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO Sink"),
            metadata(raw[2:4], (29, 28), "APDO Type", "SPR PPS"),
            metadata(raw[4:7], (27, 25), "Reserved"),
            metadata(raw[7:15], (24, 17), "Maximum Voltage", f"{int(raw[7:15], 2) / 10}V"),
            metadata(raw[15:16], (16, 16), "Reserved"),
            metadata(raw[16:24], (15, 8), "Minimum Voltage", f"{int(raw[16:24], 2) / 10}V"),
            metadata(raw[24:25], (7, 7), "Reserved"),
            metadata(raw[25:32], (6, 0), "Maximum Current", f"{int(raw[25:32], 2) / 20}A"),
        ]


class EPR_AVS_PDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO"),
            metadata(raw[2:4], (29, 28), "APDO Type", "EPR AVS"),
            metadata(raw[4:6], (27, 26), "Peak Current", raw[4:6]),
            metadata(raw[6:15], (25, 17), "Maximum Voltage", f"{int(raw[6:15], 2) / 10}V"),
            metadata(raw[15:16], (16, 16), "Reserved"),
            metadata(raw[16:24], (15, 8), "Minimum Voltage", f"{int(raw[16:24], 2) / 10}V"),
            metadata(raw[24:32], (7, 0), "PDP", f"{int(raw[24:32], 2)}W"),
        ]

        self._quick_pdo = f"A {int(raw[16:24], 2) / 10}-{int(raw[6:15], 2) / 10}V@{int(raw[24:32], 2)}W"

    def quick_pdo(self) -> str:
        return self._quick_pdo


class EPR_AVS_PDO_S(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO Sink"),
            metadata(raw[2:4], (29, 28), "APDO Type", "EPR AVS"),
            metadata(raw[4:6], (27, 26), "Reserved"),
            metadata(raw[6:15], (25, 17), "Maximum Voltage", f"{int(raw[6:15], 2) / 10}V"),
            metadata(raw[15:16], (16, 16), "Reserved"),
            metadata(raw[16:24], (15, 8), "Minimum Voltage", f"{int(raw[16:24], 2) / 10}V"),
            metadata(raw[24:32], (7, 0), "PDP", f"{int(raw[24:32], 2)}W"),
        ]


class SPR_AVS_PDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO"),
            metadata(raw[2:4], (29, 28), "APDO Type", "SPR AVS"),
            metadata(raw[4:6], (27, 26), "Peak Current", raw[4:6]),
            metadata(raw[6:12], (25, 20), "Reserved"),
            metadata(raw[12:22], (19, 10), "Maximum Current 15V", f"{int(raw[12:22], 2) / 100}A"),
            metadata(raw[22:32], (9, 0), "Maximum Current 20V", f"{int(raw[22:32], 2) / 100}A"),
        ]

        self._quick_pdo = f"A 9-15V@{int(raw[12:22], 2) / 100}A 15-20V@{int(raw[22:32], 2) / 100}A"

    def quick_pdo(self) -> str:
        return self._quick_pdo


class SPR_AVS_PDO_S(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO Sink"),
            metadata(raw[2:4], (29, 28), "APDO Type", "SPR AVS"),
            metadata(raw[4:12], (27, 20), "Reserved"),
            metadata(raw[12:22], (19, 10), "Maximum Current 15V", f"{int(raw[12:22], 2) / 100}A"),
            metadata(raw[22:32], (9, 0), "Maximum Current 20V", f"{int(raw[22:32], 2) / 100}A"),
        ]


class F_VRDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str, **kwargs):
        super().__init__(raw, bit_loc, field)
        self._pdo = kwargs["pdo"]
        self._value = [
            metadata(raw[0:4], (31, 28), "Object Position", int(raw[0:4], 2)),
            metadata(raw[4:5], (27, 27), "Giveback", bool(int(raw[4:5]))),
            metadata(raw[5:6], (26, 26), "Capability Mismatch", bool(int(raw[5:6]))),
            metadata(raw[6:7], (25, 25), "USB Communications Capable", bool(int(raw[6:7]))),
            metadata(raw[7:8], (24, 24), "No USB Suspend", bool(int(raw[7:8]))),
            metadata(raw[8:9], (23, 23), "Unchunked Extended Messages Supported", bool(int(raw[8:9]))),
            metadata(raw[9:10], (22, 22), "EPR Capable", bool(int(raw[9:10]))),
            metadata(raw[10:12], (21, 20), "Reserved"),
            metadata(raw[12:22], (19, 10), "Operating Current", f"{int(raw[12:22], 2) / 100}A"),
            metadata(raw[22:32], (9, 0), "Maximum Operating Current", f"{int(raw[22:32], 2) / 100}A"),
        ]

        if self._pdo["Supply Type"].value() == "FPDO":
            if self._value[0].value() < 8:
                self._quick_rdo = f"[{self._value[0].value()}] F {self._pdo['Voltage'].value()}@{self._value[8].value()}"
            else:
                self._quick_rdo = f"[{self._value[0].value()}] EF {self._pdo['Voltage'].value()}@{self._value[8].value()}"
        elif self._pdo["Supply Type"].value() == "VPDO":
            if self._value[0].value() < 8:
                self._quick_rdo = (f"[{self._value[0].value()}] V {self._pdo['Minimum Voltage'].value()[:-1]}"
                                   f"-{self._pdo['Maximum Voltage'].value()}@{self._value[8].value()}")
            else:
                self._quick_rdo = (f"[{self._value[0].value()}] EV {self._pdo['Minimum Voltage'].value()[:-1]}"
                                   f"-{self._pdo['Maximum Voltage'].value()}@{self._value[8].value()}")

    def pdo(self) -> metadata:
        return self._pdo
    
    def quick_rdo(self) -> str:
        return self._quick_rdo


class BRDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str, **kwargs):
        super().__init__(raw, bit_loc, field)
        self._pdo = kwargs["pdo"]
        self._value = [
            metadata(raw[0:4], (31, 28), "Object Position", int(raw[0:4], 2)),
            metadata(raw[4:5], (27, 27), "Giveback", bool(int(raw[4:5]))),
            metadata(raw[5:6], (26, 26), "Capability Mismatch", bool(int(raw[5:6]))),
            metadata(raw[6:7], (25, 25), "USB Communications Capable", bool(int(raw[6:7]))),
            metadata(raw[7:8], (24, 24), "No USB Suspend", bool(int(raw[7:8]))),
            metadata(raw[8:9], (23, 23), "Unchunked Extended Messages Supported", bool(int(raw[8:9]))),
            metadata(raw[9:10], (22, 22), "EPR Capable", bool(int(raw[9:10]))),
            metadata(raw[10:12], (21, 20), "Reserved"),
            metadata(raw[12:22], (19, 10), "Operating Power", f"{int(raw[12:22], 2) / 4}W"),
            metadata(raw[22:32], (9, 0), "Maximum Operating Power", f"{int(raw[22:32], 2) / 4}W"),
        ]

        if self._value[0].value() < 8:
            self._quick_rdo = (f"[{self._value[0].value()}] B {self._pdo['Minimum Voltage'].value()[:-1]}"
                               f"-{self._pdo['Maximum Voltage'].value()}@{self._value[8].value()}")
        else:
            self._quick_rdo = (f"[{self._value[0].value()}] EB {self._pdo['Minimum Voltage'].value()[:-1]}"
                               f"-{self._pdo['Maximum Voltage'].value()}@{self._value[8].value()}")
    
    def pdo(self) -> metadata:
        return self._pdo
    
    def quick_rdo(self) -> str:
        return self._quick_rdo


class PPS_RDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str, **kwargs):
        super().__init__(raw, bit_loc, field)
        self._pdo = kwargs["pdo"]
        self._value = [
            metadata(raw[0:4], (31, 28), "Object Position", int(raw[0:4], 2)),
            metadata(raw[4:5], (27, 27), "Reserved"),
            metadata(raw[5:6], (26, 26), "Capability Mismatch", bool(int(raw[5:6]))),
            metadata(raw[6:7], (25, 25), "USB Communications Capable", bool(int(raw[6:7]))),
            metadata(raw[7:8], (24, 24), "No USB Suspend", bool(int(raw[7:8]))),
            metadata(raw[8:9], (23, 23), "Unchunked Extended Messages Supported", bool(int(raw[8:9]))),
            metadata(raw[9:10], (22, 22), "EPR Capable", bool(int(raw[9:10]))),
            metadata(raw[10:11], (21, 21), "Reserved"),
            metadata(raw[11:23], (20, 9), "Output Voltage", f"{int(raw[11:23], 2) / 50}V"),
            metadata(raw[23:25], (8, 7), "Reserved"),
            metadata(raw[25:32], (6, 0), "Operating Current", f"{int(raw[25:32], 2) / 20}A"),
        ]

        self._quick_rdo = f"[{self._value[0].value()}] P {self._value[8].value()}@{self._value[10].value()}"
    
    def pdo(self) -> metadata:
        return self._pdo
    
    def quick_rdo(self) -> str:
        return self._quick_rdo


class AVS_RDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, field: str, **kwargs):
        super().__init__(raw, bit_loc, field)
        self._pdo = kwargs["pdo"]
        self._value = [
            metadata(raw[0:4], (31, 28), "Object Position", int(raw[0:4], 2)),
            metadata(raw[4:5], (27, 27), "Reserved"),
            metadata(raw[5:6], (26, 26), "Capability Mismatch", bool(int(raw[5:6]))),
            metadata(raw[6:7], (25, 25), "USB Communications Capable", bool(int(raw[6:7]))),
            metadata(raw[7:8], (24, 24), "No USB Suspend", bool(int(raw[7:8]))),
            metadata(raw[8:9], (23, 23), "Unchunked Extended Messages Supported", bool(int(raw[8:9]))),
            metadata(raw[9:10], (22, 22), "EPR Capable", bool(int(raw[9:10]))),
            metadata(raw[10:11], (21, 21), "Reserved"),
            metadata(raw[11:23], (20, 9), "Output Voltage", f"{int(raw[11:23], 2) / 40}V"),
            metadata(raw[23:25], (8, 7), "Reserved"),
            metadata(raw[25:32], (6, 0), "Operating Current", f"{int(raw[25:32], 2) / 20}A"),
        ]

        if self._value[0].value() < 8:
            self._quick_rdo = f"[{self._value[0].value()}] A {self._value[8].value()}@{self._value[10].value()}"
        else:
            self._quick_rdo = f"[{self._value[0].value()}] EA {self._value[8].value()}@{self._value[10].value()}"

    def pdo(self) -> metadata:
        return self._pdo
    
    def quick_rdo(self) -> str:
        return self._quick_rdo


class ID_Header_VDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple, **kwargs):
        super().__init__(raw, bit_loc, "ID Header VDO")
        sop = kwargs["sop"]

        SOP_Product_Type_UFP = {
            "000": "Not a UFP",
            "001": "PDUSB Hub",
            "010": "PDUSB Peripheral",
            "011": "PSD"
        }

        SOP1_Product_Type = {
            "000": "Not a Cable Plug/VPD",
            "011": "Passive Cable",
            "100": "Active Cable",
            "110": "VCONN-Powered USB Device (VPD)"
        }

        SOP_Product_Type_DFP = {
            "000": "Not a DFP",
            "001": "PDUSB Hub",
            "010": "PDUSB Host",
            "011": "Power Brick",
        }

        Connector_Type = {
            "10": "USB Type-C Receptacle",
            "11": "USB Type-C Plug"
        }

        self._value = [
            metadata(raw[0:1], (31, 31), "USB Host", bool(int(raw[0:1]))),
            metadata(raw[1:2], (30, 30), "USB Device", bool(int(raw[1:2])))
        ]

        if sop == "SOP":
            self._value.append(metadata(raw[2:5], (29, 27), "Product Type (UFP)",
                                        SOP_Product_Type_UFP.get(raw[2:5], "Reserved")))
        elif sop == "SOP'":
            self._value.append(metadata(raw[2:5], (29, 27), "Product Type (Cable Plug/VPD)",
                                        SOP1_Product_Type.get(raw[2:5], "Reserved")))
        else:
            self._value.append(metadata(raw[2:5], (29, 27), "Reserved"))

        self._value.append(metadata(raw[5:6], (26, 26), "Modal Operation Supported", bool(int(raw[5:6]))))

        if sop == "SOP":
            self._value.append(metadata(raw[6:9], (25, 23), "Product Type (DFP)",
                                        SOP_Product_Type_DFP.get(raw[6:9], "Reserved")))
        else:
            self._value.append(metadata(raw[6:9], (25, 23), "Reserved"))

        self._value.extend([
            metadata(raw[9:11], (22, 21), "Connector Type", Connector_Type.get(raw[9:11], "Reserved")),
            metadata(raw[11:16], (20, 16), "Reserved"),
            metadata(raw[16:32], (15, 0), "USB Vendor ID", f"0x{int(raw[16:32], 2):04X}")
        ])


class UFP_VDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple):
        super().__init__(raw, bit_loc, "UFP VDO")

        Version = {
            "000": "Version 1.0",
            "001": "Version 1.1",
            "010": "Version 1.2",
            "011": "Version 1.3",
        }

        VCONN_Power = {
            "000": "1W",
            "001": "1.5W",
            "010": "2W",
            "011": "3W",
            "100": "4W",
            "101": "5W",
            "110": "6W",
        }

        USB_Highest_Speed = {
            "000": "[USB 2.0] only",
            "001": "[USB 3.2] Gen1",
            "010": "[USB 3.2]/[USB 4] Gen2",
            "011": "[USB4] Gen3",
            "100": "[USB4] Gen4",
        }

        self._value = [
            metadata(raw[0:3], (31, 29), "UFP VDO Version", Version.get(raw[0:3], "Reserved")),
            metadata(raw[3:4], (28, 28), "Reserved"),
        ]

        Device_Capability = [
            metadata(raw[4:5], (27, 27), "[USB 2.0] Device Capable", bool(int(raw[4:5]))),
            metadata(raw[5:6], (26, 26), "[USB 2.0] Device Capable (Billboard only)", bool(int(raw[5:6]))),
            metadata(raw[6:7], (25, 25), "[USB 3.2] Device Capable", bool(int(raw[6:7]))),
            metadata(raw[7:8], (24, 24), "[USB4] Device Capable", bool(int(raw[7:8]))),
        ]
        self._value.extend([
            metadata(raw[4:8], (27, 24), "Device Capability", Device_Capability),
            metadata(raw[8:10], (23, 22), "Connector Type (Legacy)", "Deprecated"),
            metadata(raw[10:21], (21, 11), "Reserved"),
            metadata(raw[21:24], (10, 8), "VCONN Power",
                     VCONN_Power.get(raw[21:24], "Reserved") if bool(int(raw[24:25])) else "Reserved"),
            metadata(raw[24:25], (7, 7), "VCONN Required", bool(int(raw[24:25]))),
            metadata(raw[25:26], (6, 6), "VBUS Required", bool(1 - int(raw[25:26]))),
        ])

        Alternate_Modes =[
            metadata(raw[26:27], (5, 5), "Supports [TBT3]", bool(int(raw[26:27]))),
            metadata(raw[27:28], (4, 4), "Supports [USB Type-C 2.4] excl. [TBT3]", bool(int(raw[27:28]))),
            metadata(raw[28:29], (3, 3), "Supports [USB Type-C 2.4] Non-Reconfigurable", bool(int(raw[28:29]))),
        ]
        self._value.append(metadata(raw[26:29], (5, 3), "Alternate Modes", Alternate_Modes))
        self._value.append(metadata(raw[29:32], (2, 0), "USB Highest Speed", USB_Highest_Speed.get(raw[29:32], "Reserved")))


class DFP_VDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple):
        super().__init__(raw, bit_loc, "DFP VDO")

        Version = {
            "000": "Version 1.0",
            "001": "Version 1.1",
            "010": "Version 1.2",
        }

        self._value = [
            metadata(raw[0:3], (31, 29), "DFP VDO Version", Version.get(raw[0:3], "Reserved")),
            metadata(raw[3:5], (28, 27), "Reserved")
        ]

        Host_Capability = [
            metadata(raw[5:6], (26, 26), "[USB 2.0] Host Capable", bool(int(raw[5:6]))),
            metadata(raw[6:7], (25, 25), "[USB 3.2] Host Capable", bool(int(raw[6:7]))),
            metadata(raw[7:8], (24, 24), "[USB4] Host Capable", bool(int(raw[7:8]))),
        ]

        self._value.extend([
            metadata(raw[5:8], (26, 24), "Host Capability", Host_Capability),
            metadata(raw[8:10], (23, 22), "Connector Type (Legacy)", "Deprecated"),
            metadata(raw[10:27], (21, 5), "Reserved"),
            metadata(raw[27:32], (4, 0), "Port Number", int(raw[27:32], 2)),
        ])


class Passive_Cable_VDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple):
        super().__init__(raw, bit_loc, "Passive Cable VDO")

        UTPTUTC = {
            "10": "USB Type-C",
            "11": "Captive"
        }

        Cable_Latency = {
            "0001": "<10ns (~1m)",
            "0010": "10ns to 20ns (~2m)",
            "0011": "20ns to 30ns (~3m)",
            "0100": "30ns to 40ns (~4m)",
            "0101": "40ns to 50ns (~5m)",
            "0110": "50ns to 60ns (~6m)",
            "0111": "60ns to 70ns (~7m)",
            "1000": "> 70ns (>~7m)",
        }

        Cable_Termination_Type = {
            "00": "VCONN not required",
            "01": "VCONN required",
        }

        Maximum_VBUS_Voltage = {
            "00": "20V",
            "01": "30V",
            "10": "40V",
            "11": "50V",
        }

        VBUS_Current_Handling_Capability = {
            "01": "3A",
            "10": "5A",
        }

        USB_Highest_Speed = {
            "000": "[USB 2.0] only",
            "001": "[USB 3.2] Gen1",
            "010": "[USB 3.2]/[USB 4] Gen2",
            "011": "[USB4] Gen3",
            "100": "[USB4] Gen4",
        }

        self._value = [
            metadata(raw[0:4], (31, 28), "HW Version", int(raw[0:4], 2)),
            metadata(raw[4:8], (27, 24), "Firmware Version", int(raw[4:8], 2)),
            metadata(raw[8:11], (23, 21), "VDO Version", "Version 1.0" if raw[8:11] == "000" else "Reserved"),
            metadata(raw[11:12], (20, 20), "Reserved"),
            metadata(raw[12:14], (19, 18), "USB Type-C plug to USB Type-C/Captive (Passive Cable)",
                     UTPTUTC.get(raw[12:14], "Reserved")),
            metadata(raw[14:15], (17, 17), "EPR Capable (Passive Cable)", bool(int(raw[14:15]))),
            metadata(raw[15:19], (16, 13), "Cable Latency (Passive Cable)", Cable_Latency.get(raw[15:19], "Reserved")),
            metadata(raw[19:21], (12, 11), "Cable Termination Type (Passive Cable)",
                     Cable_Termination_Type.get(raw[19:21], "Reserved")),
            metadata(raw[21:23], (10, 9), "Maximum VBUS Voltage (Passive Cable)",
                     Maximum_VBUS_Voltage.get(raw[21:23], "Reserved")),
            metadata(raw[23:25], (8, 7), "Reserved"),
            metadata(raw[25:27], (6, 5), "VBUS Current Handling Capability (Passive Cable)",
                     VBUS_Current_Handling_Capability.get(raw[25:27], "Reserved")),
            metadata(raw[27:29], (4, 3), "Reserved"),
            metadata(raw[29:32], (2, 0), "USB Highest Speed (Passive Cable)",
                     USB_Highest_Speed.get(raw[29:32], "Reserved")),
        ]


class Active_Cable_VDO1(metadata):
    def __init__(self, raw: str, bit_loc: tuple):
        super().__init__(raw, bit_loc, "Active Cable VDO 1")

        UTPTUTC = {
            "10": "USB Type-C",
            "11": "Captive"
        }

        Cable_Latency = {
            "0001": "<10ns (~1m)",
            "0010": "10ns to 20ns (~2m)",
            "0011": "20ns to 30ns (~3m)",
            "0100": "30ns to 40ns (~4m)",
            "0101": "40ns to 50ns (~5m)",
            "0110": "50ns to 60ns (~6m)",
            "0111": "60ns to 70ns (~7m)",
            "1000": "1000ns (~100m)",
            "1001": "2000ns (~200m)",
            "1010": "3000ns (~300m)",
        }

        Cable_Termination_Type = {
            "10": "One end Active, one end passive, VCONN required",
            "11": "Both ends Active, VCONN required",
        }

        Maximum_VBUS_Voltage = {
            "00": "20V",
            "01": "30V",
            "10": "40V",
            "11": "50V",
        }

        VBUS_Current_Handling_Capability = {
            "01": "3A",
            "10": "5A",
        }

        USB_Highest_Speed = {
            "000": "[USB 2.0] only",
            "001": "[USB 3.2] Gen1",
            "010": "[USB 3.2]/[USB 4] Gen2",
            "011": "[USB4] Gen3",
            "100": "[USB4] Gen4",
        }

        self._value = [
            metadata(raw[0:4], (31, 28), "HW Version", int(raw[0:4], 2)),
            metadata(raw[4:8], (27, 24), "Firmware Version", int(raw[4:8], 2)),
            metadata(raw[8:11], (23, 21), "VDO Version", "Version 1.0" if raw[8:11] == "000" else "Reserved"),
            metadata(raw[11:12], (20, 20), "Reserved"),
            metadata(raw[12:14], (19, 18), "USB Type-C plug to USB Type-C/Captive",
                     UTPTUTC.get(raw[12:14], "Reserved")),
            metadata(raw[14:15], (17, 17), "EPR Capable (Active Cable)", bool(int(raw[14:15]))),
            metadata(raw[15:19], (16, 13), "Cable Latency", Cable_Latency.get(raw[15:19], "Reserved")),
            metadata(raw[19:21], (12, 11), "Cable Termination Type (Active Cable)",
                     Cable_Termination_Type.get(raw[19:21], "Reserved")),
            metadata(raw[21:23], (10, 9), "Maximum VBUS Voltage (Active Cable)",
                     Maximum_VBUS_Voltage.get(raw[21:23], "Reserved")),
            metadata(raw[23:24], (8, 8), "SBU Supported", bool(1 - int(raw[23:24]))),
        ]

        if raw[23:24] == "0":
            self._value.append(metadata(raw[24:25], (7, 7), "SBU Type",
                                        "SBU is active" if bool(int(raw[24:25])) else "SBU is passive"))
        else:
            self._value.append(metadata(raw[24:25], (7, 7), "Reserved"))

        self._value.extend([
            metadata(raw[25:27], (6, 5), "VBUS Current Handling Capability (Active Cable)",
                     VBUS_Current_Handling_Capability.get(raw[25:27], "Reserved")),
            metadata(raw[27:28], (4, 4), "VBUS Through Cable", bool(int(raw[27:28]))),
            metadata(raw[28:29], (3, 3), "SOP'' Controller Present", bool(int(raw[28:29]))),
            metadata(raw[29:32], (2, 0), "USB Highest Speed (Active Cable)", USB_Highest_Speed.get(raw[29:32], "Reserved")),
        ])


class Active_Cable_VDO2(metadata):
    def __init__(self, raw: str, bit_loc: tuple):
        super().__init__(raw, bit_loc, "Active Cable VDO 2")

        U3_CLd_Power = {
            "000": ">10mW",
            "001": "5-10mW",
            "010": "1-5mW",
            "011": "0.5-1mW",
            "100": "0.2-0.5mW",
            "101": "50-200μW",
            "110": "<50μW",
        }

        self._value = [
            metadata(raw[0:8], (31, 24), "Maximum Operating Temperature", f"{int(raw[0:8], 2)}°C"),
            metadata(raw[8:16], (23, 16), "Shutdown Temperature", f"{int(raw[8:16], 2)}°C"),
            metadata(raw[16:17], (15, 15), "Reserved"),
            metadata(raw[17:20], (14, 12), "U3/CLd Power", U3_CLd_Power.get(raw[17:20], "Reserved")),
            metadata(raw[20:21], (11, 11), "U3 to U0 transition mode",
                     "U3 to U0 through U3S" if bool(int(raw[20:21])) else "U3 to U0 direct"),
            metadata(raw[21:22], (10, 10), "Physical connection",
                     "Optical" if bool(int(raw[21:22])) else "Copper"),
            metadata(raw[22:23], (9, 9), "Active element",
                     "Active Re-timer" if bool(int(raw[22:23])) else "Active Re-driver"),
            metadata(raw[23:24], (8, 8), "USB4 Supported", bool(1 - int(raw[23:24]))),
            metadata(raw[24:26], (7, 6), "USB 2.0 Hub Hops Consumed", int(raw[24:26], 2)),
            metadata(raw[26:27], (5, 5), "USB 2.0 Supported", bool(1 - int(raw[26:27]))),
            metadata(raw[27:28], (4, 4), "USB 3.2 Supported", bool(1 - int(raw[27:28]))),
            metadata(raw[28:29], (3, 3), "USB Lanes Supported"
                     "Two lanes" if bool(int(raw[28:29])) else "One lane"),
            metadata(raw[29:30], (2, 2), "Optically Isolated Active Cable", bool(int(raw[29:30]))),
            metadata(raw[30:31], (1, 1), "USB4 Asymmetric Mode Supported", bool(int(raw[30:31]))),
            metadata(raw[31:32], (0, 0), "USB Gen",
                     "Gen 2 or higher" if bool(int(raw[31:32])) else "Gen 1"),
        ]


class VPD_VDO(metadata):
    def __init__(self, raw: str, bit_loc: tuple):
        super().__init__(raw, bit_loc, "VPD VDO")

        Maximum_VBUS_Voltage = {
            "00": "20V",
            "01": "30V",
            "10": "40V",
            "11": "50V",
        }

        self._value = [
            metadata(raw[0:4], (31, 28), "HW Version", int(raw[0:4], 2)),
            metadata(raw[4:8], (27, 24), "Firmware Version", int(raw[4:8], 2)),
            metadata(raw[8:11], (23, 21), "VDO Version", "Version 1.0" if raw[8:11] == "000" else "Reserved"),
            metadata(raw[11:15], (20, 17), "Reserved"),
            metadata(raw[15:17], (16, 15), "Maximum VBUS Voltage",
                     Maximum_VBUS_Voltage.get(raw[15:17], "Reserved")),
        ]

        if bool(int(raw[31:32])):
            self._value.extend([
                metadata(raw[17:18], (14, 14), "Charge Through Current Support",
                         "5A Capable" if bool(int(raw[17:18])) else "3A Capable"),
                metadata(raw[18:19], (13, 13), "Reserved"),
                metadata(raw[19:25], (12, 7), "VBUS Impedance", f"{int(raw[19:25], 2)*2}mΩ"),
                metadata(raw[25:31], (6, 1), "Ground Impedance", f"{int(raw[25:31], 2)}mΩ"),
                metadata(raw[31:32], (0, 0), "Charge Through Support", bool(int(raw[31:32]))),
            ])
        else:
            self._value.extend([
                metadata(raw[17:18], (14, 14), "Charge Through Current Support", "Reserved"),
                metadata(raw[18:19], (13, 13), "Reserved"),
                metadata(raw[19:25], (12, 7), "VBUS Impedance", "Reserved"),
                metadata(raw[25:31], (6, 1), "Ground Impedance", "Reserved"),
                metadata(raw[31:32], (0, 0), "Charge Through Support", bool(int(raw[31:32]))),
            ])


def pdo_type(raw: str) -> type:
    if raw[0:2] == "00":
        return FPDO
    elif raw[0:2] == "01":
        return BPDO
    elif raw[0:2] == "10":
        return VPDO
    elif raw[0:2] == "11":
        if raw[2:4] == "00":
            return PPS_PDO
        elif raw[2:4] == "01":
            return EPR_AVS_PDO
        elif raw[2:4] == "10":
            return SPR_AVS_PDO
        elif raw[2:4] == "11":
            return metadata


def sink_pdo_type(raw: str) -> type:
    if raw[0:2] == "00":
        return FPDO_S
    elif raw[0:2] == "01":
        return BPDO_S
    elif raw[0:2] == "10":
        return VPDO_S
    elif raw[0:2] == "11":
        if raw[2:4] == "00":
            return PPS_PDO_S
        elif raw[2:4] == "01":
            return EPR_AVS_PDO_S
        elif raw[2:4] == "10":
            return SPR_AVS_PDO_S
        elif raw[2:4] == "11":
            return metadata


def rdo_type(pdo: metadata) -> type:
    if pdo["Supply Type"].value() == "FPDO":
        return F_VRDO
    elif pdo["Supply Type"].value() == "VPDO":
        return F_VRDO
    elif pdo["Supply Type"].value() == "BPDO":
        return BRDO
    elif pdo["Supply Type"].value() == "APDO":
        if pdo["APDO Type"].value() == "SPR PPS":
            return PPS_RDO
        elif pdo["APDO Type"].value() == "SPR AVS":
            return AVS_RDO
        elif pdo["APDO Type"].value() == "EPR AVS":
            return AVS_RDO


class Source_Capabilities(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        num_objs = kwargs["header"][1].value()
        self._value = []
        for i in range(num_objs):
            sub_raw = lst2str(data[i*4:(i+1)*4])
            self._value.append(pdo_type(sub_raw)(sub_raw, (i*32, (i+1)*32-1), f"PDO {i+1}"))


class Request(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        if "last_pdo" not in kwargs:
            self._value = "Invalid Request Message"
        pdo_list = kwargs["last_pdo"]["Data Objects"].value()
        sub_raw = lst2str(data[0:4])
        pdo = pdo_list[int(sub_raw[0:4], 2) - 1]
        self._value = [(rdo_type(pdo)(sub_raw, (0, 31), "RDO", pdo=pdo))]


class BIST(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        num_objs = kwargs["header"][1].value()

        BIST_Mode = {
            "0101": "BIST Carrier Mode",
            "1000": "BIST Test Data",
            "1001": "BIST Shared Test Mode Entry",
            "1010": "BIST Shared Test Mode Exit",
        }

        sub_raw = lst2str(data[0:4])
        BIST_Data_Object = [
            metadata(sub_raw[0:4], (31, 28), "BIST Mode", BIST_Mode.get(sub_raw[0:4], "Reserved")),
            metadata(sub_raw[4:32], (27, 0), "Reserved"),
        ]

        self._value = [(metadata(sub_raw, (0, 31), "BIST Data Object", BIST_Data_Object))]

        if num_objs > 1:
            self._value.append(metadata(lst2str(data[4:num_objs*4]), (32, num_objs*32-1), "Test Data",
                                        f'0x{bytes(data[4:num_objs*4][::-1]).hex().upper()}'))


class Sink_Capabilities(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        num_objs = kwargs["header"][1].value()
        self._value = []
        for i in range(num_objs):
            sub_raw = lst2str(data[i*4:(i+1)*4])
            self._value.append(sink_pdo_type(sub_raw)(sub_raw, (i*32, (i+1)*32-1), f"PDO {i+1}"))


class Battery_Status(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")

        BC_Status = {
            "00": "Battery is Charging",
            "01": "Battery is Discharging",
            "10": "Battery is Idle",
        }

        self._raw = lst2str(data, '>')
        BSDO_raw = lst2str(data[0:4])

        Batter_Info = [
            metadata(BSDO_raw[23:24], (0, 0), "Invalid Battery Reference", bool(int(BSDO_raw[23:24]))),
            metadata(BSDO_raw[22:23], (1, 1), "Battery Present", bool(int(BSDO_raw[22:23]))),
            metadata(BSDO_raw[20:22], (3, 2), "Battery Charging Status",
                     BC_Status.get(BSDO_raw[20:22], "Reserved") if bool(int(BSDO_raw[22:23])) else "Reserved"),
            metadata(BSDO_raw[16:20], (7, 4), "Reserved")
        ]

        BSDO = [
            metadata(BSDO_raw[0:16], (31, 16), "Battery Present Capacity", f"{int(BSDO_raw[0:16], 2) / 10}Wh"),
            metadata(BSDO_raw[16:24], (15, 8), "Battery Info", Batter_Info),
            metadata(BSDO_raw[24:32], (7, 0), "Reserved")
        ]

        self._value = [metadata(BSDO_raw, (0, 31), "BSDO", BSDO)]


class Alert(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")

        EAET = {
            "0001": "Power State Change",
            "0010": "Power Button Press",
            "0011": "Power Button Release",
            "0100": "Controller Initiated Wake"
        }

        self._raw = lst2str(data, '>')
        ppr = kwargs["header"][3].value()
        ADO_raw = lst2str(data[0:4])
        Type_of_Alert = [
            metadata(ADO_raw[7:8], (0, 0), "Reserved"),
            metadata(ADO_raw[6:7], (1, 1), "Battery Status Changed Event", bool(int(ADO_raw[6:7]))),
            metadata(ADO_raw[5:6], (2, 2), "OCP Event", bool(int(ADO_raw[5:6]))),
        ]

        if ppr == "Source":
            Type_of_Alert.append(metadata(ADO_raw[4:5], (3, 3), "OTP Event", bool(int(ADO_raw[4:5]))))
        elif ppr == "Sink":
            Type_of_Alert.append(metadata(ADO_raw[4:5], (3, 3), "Reserved"))
        
        Type_of_Alert.extend([
            metadata(ADO_raw[3:4], (4, 4), "Operating Condition Change", bool(int(ADO_raw[3:4]))),
            metadata(ADO_raw[2:3], (5, 5), "Source Input Change Event", bool(int(ADO_raw[2:3]))),
            metadata(ADO_raw[1:2], (6, 6), "OVP Event", bool(int(ADO_raw[1:2]))),
            metadata(ADO_raw[0:1], (7, 7), "Extended Alert Event", bool(int(ADO_raw[0:1])))
        ])

        ADO = [
            metadata(ADO_raw[0:8], (31, 24), "Type of Alert", Type_of_Alert),
            metadata(ADO_raw[8:12], (23, 20), "Fixed Batteries", ADO_raw[8:12]),
            metadata(ADO_raw[12:16], (19, 16), "Hot Swappable Batteries", ADO_raw[12:16]),
            metadata(ADO_raw[16:28], (15, 4), "Reserved"),
            metadata(ADO_raw[28:32], (3, 0), "Extended Alert Event Type",
                     EAET.get(ADO_raw[28:32], "Reserved") if bool(int(ADO_raw[0:1])) else "Reserved")
        ]
        
        self._value = [metadata(ADO_raw, (0, 31), "ADO", ADO)]


class Get_Country_Info(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        CCDO_raw = lst2str(data[0:4])
        CCDO = [
            metadata(CCDO_raw[0:8], (31, 24), "First character of the Alpha-2 Country Code",
                     f"0x{int(CCDO_raw[0:8], 2):02X}"),
            metadata(CCDO_raw[8:16], (23, 16), "Second character of the Alpha-2 Country Code",
                     f"0x{int(CCDO_raw[8:16], 2):02X}"),
            metadata(CCDO_raw[16:32], (15, 0), "Reserved")
        ]
        self._value = [metadata(CCDO_raw, (0, 31), "CCDO", CCDO)]


class Enter_USB(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")

        USB_Mode = {
            "000": "[USB 2.0]",
            "001": "[USB 3.2]",
            "010": "[USB4]",
        }

        Cable_Speed = {
            "000": "[USB 2.0] Only",
            "001": "[USB 3.2] Gen1",
            "010": "[USB 3.2] Gen2 and [USB4] Gen2",
            "011": "[USB4] Gen3",
            "100": "[USB4] Gen4",
        }

        Cable_Type = {
            "00": "Passive",
            "01": "Active Re-timer",
            "10": "Active Re-driver",
            "11": "Optical Isolated",
        }

        Cable_Current = {
            "00": "VBUS is not supported",
            "10": "3A",
            "11": "5A",
        }

        self._raw = lst2str(data, '>')
        EUDO_raw = lst2str(data[0:4])
        EUDO = [
            metadata(EUDO_raw[0:1], (31, 31), "Reserved"),
            metadata(EUDO_raw[1:4], (30, 28), "USB Mode", USB_Mode.get(EUDO_raw[1:4], "Reserved")),
            metadata(EUDO_raw[4:5], (27, 27), "Reserved"),
            metadata(EUDO_raw[5:6], (26, 26), "USB4 DRD", "Capable" if bool(int(EUDO_raw[5:6])) else "Not Capable"),
            metadata(EUDO_raw[6:7], (25, 25), "USB3 DRD", "Capable" if bool(int(EUDO_raw[6:7])) else "Not Capable"),
            metadata(EUDO_raw[7:8], (24, 24), "Reserved"),
            metadata(EUDO_raw[8:11], (23, 21), "Cable Speed", Cable_Speed.get(EUDO_raw[8:11], "Reserved")),
            metadata(EUDO_raw[11:13], (20, 19), "Cable Type", Cable_Type.get(EUDO_raw[11:13], "Reserved")),
            metadata(EUDO_raw[13:15], (18, 17), "Cable Current", Cable_Current.get(EUDO_raw[13:15], "Reserved")),
            metadata(EUDO_raw[15:16], (16, 16), "PCIe Support", bool(int(EUDO_raw[15:16]))),
            metadata(EUDO_raw[16:17], (15, 15), "DP Support", bool(int(EUDO_raw[16:17]))),
            metadata(EUDO_raw[17:18], (14, 14), "TBT Support", bool(int(EUDO_raw[17:18]))),
            metadata(EUDO_raw[18:19], (13, 13), "Host Present", bool(int(EUDO_raw[18:19]))),
            metadata(EUDO_raw[19:32], (12, 0), "Reserved")
        ]

        self._value = [metadata(EUDO_raw, (0, 31), "EUDO", EUDO)]


class EPR_Request(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        rdo_raw = lst2str(data[0:4])
        copy_of_pdo_raw = lst2str(data[4:8])
        copy_of_pdo = pdo_type(copy_of_pdo_raw)(copy_of_pdo_raw, (32, 63), "Copy of PDO")

        self._value = [
            rdo_type(copy_of_pdo)(rdo_raw, (0, 31), "RDO", pdo=copy_of_pdo),
            copy_of_pdo
        ]


class EPR_Mode(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")

        Action = {
            0: "Reserved",
            1: "Enter",
            2: "Enter Acknowledged",
            3: "Enter Succeeded",
            4: "Enter Failed",
            5: "Exit",
        }

        Data = {
            0: "Unknown cause",
            1: "Cable not EPR Capable",
            2: "Source failed to become VCONN Source",
            3: "EPR Capable bit not set in RDO",
            4: "Source unable to enter EPR Mode",
            5: "EPR Capable bit not set in PDO",
        }

        self._raw = lst2str(data, '>')
        EPRMDO = [metadata(lst2str(data[3:4]), (31, 24), "Action", Action.get(data[3:4][0], "Reserved"))]

        action_name = EPRMDO[0].value()

        if action_name == "Enter":
            EPRMDO.append(metadata(lst2str(data[2:3]), (23, 16), "Data", f"{data[2:3][0]}W"))
        elif action_name in ["Enter Acknowledged", "Enter Succeeded", "Exit"]:
            EPRMDO.append(metadata(lst2str(data[2:3]), (23, 16), "Data", "Reserved"))
        elif action_name == "Enter Failed":
            EPRMDO.append(metadata(lst2str(data[2:3]), (23, 16), "Data", Data.get(data[2:3][0], "Reserved")))

        EPRMDO.append(metadata(lst2str(data[0:2]), (15, 0), "Reserved"))

        self._value = [metadata(lst2str(data[0:4]), (0, 31), "EPRMDO", EPRMDO)]


class Source_Info(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        SIDO_raw = lst2str(data[0:4])
        SIDO = [
            metadata(SIDO_raw[0:1], (31, 31), "Port Type",
                    "Guaranteed Capability Port" if bool(int(SIDO_raw[0:1])) else "Managed Capability Port"),
            metadata(SIDO_raw[1:8], (30, 24), "Reserved"),
            metadata(SIDO_raw[8:16], (23, 16), "Port Maximum PDP", f"{int(SIDO_raw[8:16], 2)}W"),
            metadata(SIDO_raw[16:24], (15, 8), "Port Present PDP", f"{int(SIDO_raw[16:24], 2)}W"),
            metadata(SIDO_raw[24:32], (7, 0), "Port Reported PDP", f"{int(SIDO_raw[24:32], 2)}W")
        ]
        self._value = [metadata(SIDO_raw, (0, 31), "SIDO", SIDO)]


class Revision(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        RMDO_raw = lst2str(data[0:4])
        RMDO = [
            metadata(RMDO_raw[0:4], (31, 28), "Revision.major", int(RMDO_raw[0:4], 2)),
            metadata(RMDO_raw[4:8], (27, 24), "Revision.minor", int(RMDO_raw[4:8], 2)),
            metadata(RMDO_raw[8:12], (23, 20), "Version.major", int(RMDO_raw[8:12], 2)),
            metadata(RMDO_raw[12:16], (19, 16), "Version.minor", int(RMDO_raw[12:16], 2)),
            metadata(RMDO_raw[16:32], (15, 0), "Reserved")
        ]
        self._value = [metadata(RMDO_raw, (0, 31), "RMDO", RMDO)]


class Vendor_Defined(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        num_objs = kwargs["header"][1].value()
        self._value = [VDM_header(lst2str(data[0:4]), (0, 31))]

        if self._value[0]["VDM Type"].value() == "Structured":
            cmd = self._value[0]["Command"].value()
            cmd_type = self._value[0]["Command Type"].value()
            if cmd == "Discover Identity" and cmd_type in ["ACK", "NAK", "BUSY"]:
                self._value.extend([
                    ID_Header_VDO(lst2str(data[4:8]), (32, 63), sop=kwargs["sop"]),
                    metadata(lst2str(data[8:12]), (64, 95), "Cert Stat VDO", f"0x{bytes(data[8:12][::-1]).hex().upper()}")
                ])

                PVDO_raw = lst2str(data[12:16])
                PVDO = [
                    metadata(PVDO_raw[0:16], (31, 16), "USB Product ID", f"0x{int(PVDO_raw[0:16], 2):04X}"),
                    metadata(PVDO_raw[16:32], (15, 0), "bcdDevice", f"0x{int(PVDO_raw[16:32], 2):04X}")
                ]
                self._value.append(metadata(PVDO_raw, (96, 127), "Product VDO", PVDO))

                if kwargs["sop"] == "SOP'":
                    if self._value[1]["Product Type (Cable Plug/VPD)"].value() == "Active Cable":
                        self._value.append(Active_Cable_VDO1(lst2str(data[16:20]), (128, 159)))
                        self._value.append(Active_Cable_VDO2(lst2str(data[20:24]), (160, 191)))
                    elif self._value[1]["Product Type (Cable Plug/VPD)"].value() == "Passive Cable":
                        self._value.append(Passive_Cable_VDO(lst2str(data[16:20]), (128, 159)))
                    elif self._value[1]["Product Type (Cable Plug/VPD)"].value() == "VCONN-Powered USB Device (VPD)":
                        self._value.append(VPD_VDO(lst2str(data[16:20]), (128, 159)))
                elif kwargs["sop"] == "SOP":
                    UFP_need = self._value[1]["Product Type (UFP)"].value() in ["PDUSB Hub", "PDUSB Peripheral"]
                    DFP_need = self._value[1]["Product Type (DFP)"].value() in ["PDUSB Hub", "PDUSB Host", "Power Brick"]
                    if (UFP_need and DFP_need) and num_objs == 7:
                        self._value.append(UFP_VDO(lst2str(data[16:20]), (128, 159)))
                        self._value.append(metadata(lst2str(data[20:24]), (160, 191), "Padding", "Reserved"))
                        self._value.append(DFP_VDO(lst2str(data[24:28]), (192, 223)))
                    elif (UFP_need and DFP_need) and num_objs > 4:
                        for i in range(5, num_objs):
                            self._value.append(metadata(lst2str(data[i*4:(i+1)*4]), (i*32, (i+1)*32-1), f"Error VDO {i}",
                                               f"0x{bytes(data[i*4:(i+1)*4][::-1]).hex().upper()}"))
                    elif (UFP_need and not DFP_need) and num_objs > 4:
                        self._value.append(UFP_VDO(lst2str(data[16:20]), (128, 159)))
                    elif (DFP_need and not UFP_need) and num_objs > 4:
                        self._value.append(DFP_VDO(lst2str(data[16:20]), (128, 159)))
            elif cmd == "Discover SVIDs" and cmd_type in ["ACK", "NAK", "BUSY"]:
                for i in range(1, num_objs):
                    VDO_raw = lst2str(data[i*4:(i+1)*4])
                    SVID_i = metadata(VDO_raw[0:16], (31, 16), f"SVID {i * 2 - 2}", f"0x{int(VDO_raw[0:16], 2):04X}")
                    SVID_ii = metadata(VDO_raw[16:32], (15, 0), f"SVID {i * 2 - 1}", f"0x{int(VDO_raw[16:32], 2):04X}")
                    VDO = metadata(VDO_raw, (i*32, (i+1)*32-1), f"VDO {i}", [SVID_i, SVID_ii])
                    self._value.append(VDO)
            elif cmd == "Discover Modes" and cmd_type in ["ACK", "NAK", "BUSY"]:
                for i in range(1, num_objs):
                    self._value.append(metadata(lst2str(data[i*4:(i+1)*4]), (i*32, (i+1)*32-1), f"Mode {i}",
                                                f"0x{bytes(data[i*4:(i+1)*4][::-1]).hex().upper()}"))
            elif cmd in ["Enter Mode", "Exit Mode", "Attention"]:
                for i in range(1, num_objs):
                    self._value.append(metadata(lst2str(data[i*4:(i+1)*4]), (i*32, (i+1)*32-1), f"VDO {i}",
                                                f"0x{bytes(data[i*4:(i+1)*4][::-1]).hex().upper()}"))
        else:
            for i in range(1, num_objs):
                self._value.append(metadata(lst2str(data[i*4:(i+1)*4]), (i*32, (i+1)*32-1), f"VDO {i}",
                                            f"0x{bytes(data[i*4:(i+1)*4][::-1]).hex().upper()}"))


def provide_ext(msg: metadata) -> bool:
    if msg["Extended Message Header"] is None:
        return False
    ext_header = msg["Extended Message Header"]
    if ext_header["Chunked"].value():
        if not ext_header["Request Chunk"].value():
            return True
    return False


def need_ext(ext_header: ex_msg_header) -> bool:
    if ext_header["Chunked"].value():
        if ext_header["Chunk Number"].value() > 0:
            if not ext_header["Request Chunk"].value():
                return True
    return False


class Source_Capabilities_Extended(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="SCEDB")

        LSSR = {
            "00": "150mA/μs",
            "01": "500mA/μs",
        }

        Touch_Temp = {
            0: "[IEC 60950-1]",
            1: "[IEC 62368-1] TS1",
            2: "[IEC 62368-1] TS2"
        }

        self._raw = lst2str(data, '>')
        self._value = [
            metadata(lst2str(data[0:2]), (0, 15), "VID", f"0x{bytes(data[0:2][::-1]).hex().upper()}"),
            metadata(lst2str(data[2:4]), (16, 31), "PID", f"0x{bytes(data[2:4][::-1]).hex().upper()}"),
            metadata(lst2str(data[4:8]), (32, 63), "XID", f"0x{bytes(data[0:2][::-1]).hex().upper()}"),
            metadata(lst2str(data[8:9]), (64, 71), "FW Version", f"0x{bytes(data[8:9][::-1]).hex().upper()}"),
            metadata(lst2str(data[9:10]), (72, 79), "HW Version", f"0x{bytes(data[9:10][::-1]).hex().upper()}")
        ]

        VR_raw = lst2str(data[10:11])
        Voltage_Regulation = [
            metadata(VR_raw[6:8], (1, 0), "Load Step Slew Rate", LSSR.get(VR_raw[6:8], "Reserved")),
            metadata(VR_raw[5:6], (2, 2), "Load Step Magnitude", "90% IoC" if bool(int(VR_raw[5:6])) else "25% IoC"),
            metadata(VR_raw[0:5], (7, 3), "Reserved")
        ]

        self._value.append(metadata(VR_raw, (80, 87), "Voltage Regulation", Voltage_Regulation))
        self._value.append(metadata(lst2str(data[11:12]), (88, 95), "Holdup Time",
                                    f"{data[11:12][0]}ms" if bool(int(data[11:12][0])) else "Not Supported"))

        Compliance_raw = lst2str(data[12:13])
        Compliance = [
            metadata(Compliance_raw[7:8], (0, 0), "LPS compliant", bool(int(Compliance_raw[7:8]))),
            metadata(Compliance_raw[6:7], (1, 1), "PS1 compliant", bool(int(Compliance_raw[6:7]))),
            metadata(Compliance_raw[5:6], (2, 2), "PS2 compliant", bool(int(Compliance_raw[5:6]))),
            metadata(Compliance_raw[0:5], (7, 3), "Reserved")
        ]
        self._value.append(metadata(Compliance_raw, (96, 103), "Compliance", Compliance))

        TC_raw = lst2str(data[13:14])
        Touch_Current = [
            metadata(TC_raw[7:8], (0, 0), "Low touch current EPS", bool(int(TC_raw[7:8]))),
            metadata(TC_raw[6:7], (1, 1), "Ground pin supported", bool(int(TC_raw[6:7]))),
            metadata(TC_raw[5:6], (2, 2), "Ground pin intended for protective earth", bool(int(TC_raw[5:6]))),
            metadata(TC_raw[0:5], (7, 3), "Reserved")
        ]
        self._value.append(metadata(TC_raw, (104, 111), "Touch Current", Touch_Current))

        for i in range(3):
            PC_raw = lst2str(data[14+i*2:16+i*2])
            Peak_Current = [
                metadata(PC_raw[11:16], (4, 0), "Percentage Overload", f"{min(25, int(PC_raw[11:16], 2)) * 10}%"),
                metadata(PC_raw[5:11], (10, 5), "Overload Period", f"{int(PC_raw[5:11], 2) * 20}ms"),
                metadata(PC_raw[1:5], (14, 11), "Duty Cycle", f"{int(PC_raw[1:5], 2) * 5}%"),
                metadata(PC_raw[0:1], (15, 15), "VBUS Droop", bool(int(PC_raw[0:1])))
            ]
            self._value.append(metadata(PC_raw, ((14+i*2)*8, (16+i*2)*8-1), f"Peak Current{i+1}", Peak_Current))

        self._value.append(metadata(lst2str(data[20:21]), (160, 167), "Touch Temp",
                                    Touch_Temp.get(data[20:21][0], "Reserved")))
        
        SI_raw = lst2str(data[21:22])
        Source_Inputs = [metadata(SI_raw[7:8], (0, 0), "External Power Supply", bool(int(SI_raw[7:8])))]

        if bool(int(SI_raw[7:8])):
            Source_Inputs.append(metadata(SI_raw[6:7], (1, 1), "Constrained", bool(1 - int(SI_raw[6:7]))))
        else:
            Source_Inputs.append(metadata(SI_raw[6:7], (1, 1), "Reserved"))

        Source_Inputs.append(metadata(SI_raw[5:6], (2, 2), "Internal Battery", bool(int(SI_raw[5:6]))))
        Source_Inputs.append(metadata(SI_raw[0:5], (7, 3), "Reserved"))

        self._value.append(metadata(SI_raw, (168, 175), "Source Inputs", Source_Inputs))
        self._value.append(metadata(lst2str(data[22:23]), (176, 183),
                                    "Number of Batteries/Battery Slots", lst2str(data[22:23])))
        self._value.append(metadata(lst2str(data[23:24]), (184, 191), 
                                    "SPR Source PDP Rating", f"{data[23:24][0]}W"))
        self._value.append(metadata(lst2str(data[24:25]), (192, 199), 
                                    "EPR Source PDP Rating", f"{data[24:25][0]}W"))


class Status(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="SDB")

        Internal_Temp = {
            0: "Not Support",
            1: "Less than 2°C"
        }

        Temperature_Status = {
            0: "Not Supported",
            1: "Normal",
            2: "Warning",
            3: "Over Temperature"
        }

        New_Power_State = {
            "000": "Status Not Supported",
            "001": "S0",
            "010": "Modern Standby",
            "011": "S3",
            "100": "S4",
            "101": "S5",
            "110": "G3",
        }

        New_Power_State_indicator = {
            "000": "Off LED",
            "001": "On LED",
            "010": "Blinking LED",
            "011": "Breathing LED",
        }

        self._raw = lst2str(data, '>')
        self._value = [metadata(lst2str(data[0:1]), (0, 7), "Internal Temp",
                                Internal_Temp.get(data[0:1][0], f"{data[0:1][0]}°C"))]
        
        PI_raw = lst2str(data[1:2])
        Present_Input = [
            metadata(PI_raw[7:8], (0, 0), "Reserved"),
            metadata(PI_raw[6:7], (1, 1), "External Power", bool(int(PI_raw[6:7])))
        ]

        if bool(int(PI_raw[6:7])):
            Present_Input.append(metadata(PI_raw[5:6], (2, 2), "External Power Type",
                                          "AC" if bool(int(PI_raw[5:6])) else "DC"))
        else:
            Present_Input.append(metadata(PI_raw[5:6], (2, 2), "Reserved"))
        
        Present_Input.append(metadata(PI_raw[4:5], (3, 3), "Internal Power from Battery", bool(int(PI_raw[4:5]))))
        Present_Input.append(metadata(PI_raw[3:4], (4, 4), "Internal Power from non-Battery", bool(int(PI_raw[3:4]))))
        Present_Input.append(metadata(PI_raw[0:3], (7, 5), "Reserved"))

        self._value.append(metadata(PI_raw, (8, 15), "Present Input", Present_Input))

        if bool(int(PI_raw[4:5])):
            self._value.append(metadata(lst2str(data[2:3]), (16, 23), "Present Battery Input", lst2str(data[2:3])))
        else:
            self._value.append(metadata(lst2str(data[2:3]), (16, 23), "Reserved"))
        
        EF_raw = lst2str(data[3:4])
        Event_Flags = [
            metadata(EF_raw[7:8], (0, 0), "Reserved"),
            metadata(EF_raw[6:7], (1, 1), "OCP Event", bool(int(EF_raw[6:7]))),
            metadata(EF_raw[5:6], (2, 2), "OTP Event", bool(int(EF_raw[5:6]))),
            metadata(EF_raw[4:5], (3, 3), "OVP Event", bool(int(EF_raw[4:5])))
        ]

        if kwargs["last_rdo"]["Data Objects"]["RDO"].pdo().raw()[0:4] == "1100":
            Event_Flags.append(metadata(EF_raw[3:4], (4, 4), "CL/CV Mode",
                                        "CL" if bool(int(EF_raw[3:4])) else "CV"))
        else:
            Event_Flags.append(metadata(EF_raw[3:4], (4, 4), "Reserved"))

        Event_Flags.append(metadata(EF_raw[0:3], (7, 5), "Reserved"))

        self._value.append(metadata(EF_raw, (24, 31), "Event Flags", Event_Flags))

        self._value.append(metadata(lst2str(data[4:5]), (32, 39), "Temperature Status",
                                    Temperature_Status.get(data[4:5][0], "Reserved")))

        PS_raw = lst2str(data[5:6])
        Power_Status = [
            metadata(PS_raw[7:8], (0, 0), "Reserved"),
            metadata(PS_raw[6:7], (1, 1), "Cable Supported Current", bool(int(PS_raw[6:7]))),
            metadata(PS_raw[5:6], (2, 2), "Sourcing Other Ports", bool(int(PS_raw[5:6]))),
            metadata(PS_raw[4:5], (3, 3), "Insufficient External Power", bool(int(PS_raw[4:5]))),
            metadata(PS_raw[3:4], (4, 4), "Event Flags in Place", bool(int(PS_raw[3:4]))),
            metadata(PS_raw[2:3], (5, 5), "Temperature", bool(int(PS_raw[2:3]))),
            metadata(PS_raw[0:2], (7, 6), "Reserved")
        ]
        self._value.append(metadata(PS_raw, (40, 47), "Power Status", Power_Status))

        PSC_raw = lst2str(data[6:7])
        Power_State_Change = [
            metadata(PSC_raw[5:8], (2, 0), "New Power State", New_Power_State.get(PSC_raw[5:8], "Reserved")),
            metadata(PSC_raw[2:5], (5, 3), "New Power State indicator",
                     New_Power_State_indicator.get(PSC_raw[2:5], "Reserved")),
            metadata(PSC_raw[0:2], (7, 6), "Reserved")
        ]
        self._value.append(metadata(PSC_raw, (48, 55), "Power State Change", Power_State_Change))


class Get_Battery_Cap(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="GBCDB")
        self._raw = lst2str(data, '>')
        if 0 <= data[0:1][0] <= 3:
            self._value = [metadata(lst2str(data[0:1]), (0, 7), "Battery Cap Ref",
                                    f"Fixed Battery {data[0:1][0]}")]
        elif 4 <= data[0:1][0] <= 7:
            self._value = [metadata(lst2str(data[0:1]), (0, 7), "Battery Cap Ref",
                                    f"Hot Swappable Battery {data[0:1][0]-4}")]
        else:
            self._value = [metadata(lst2str(data[0:1]), (0, 7), "Battery Cap Ref", "Reserved")]


class Get_Battery_Status(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="GBSDB")
        self._raw = lst2str(data, '>')
        if 0 <= data[0:1][0] <= 3:
            self._value = [metadata(lst2str(data[0:1]), (0, 7), "Battery Status Ref",
                                    f"Fixed Battery {data[0:1][0]}")]
        elif 4 <= data[0:1][0] <= 7:
            self._value = [metadata(lst2str(data[0:1]), (0, 7), "Battery Status Ref",
                                    f"Hot Swappable Battery {data[0:1][0]-4}")]
        else:
            self._value = [metadata(lst2str(data[0:1]), (0, 7), "Battery Status Ref", "Reserved")]


class Battery_Capabilities(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="BCDB")
        self._raw = lst2str(data, '>')
        self._value = [
            metadata(lst2str(data[0:2]), (0, 15), "VID", f"0x{bytes(data[0:2][::-1]).hex().upper()}"),
            metadata(lst2str(data[2:4]), (16, 31), "PID", f"0x{bytes(data[2:4][::-1]).hex().upper()}")
        ]

        if lst2str(data[4:6]) == "0" * 16:
            self._value.append(metadata(lst2str(data[4:6]), (32, 47), "Battery Design Capacity",
                                        "Battery Not Present"))
        elif lst2str(data[4:6]) == "1" * 16:
            self._value.append(metadata(lst2str(data[4:6]), (32, 47), "Battery Design Capacity",
                                        "Design Capacity Unknown"))
        else:
            self._value.append(metadata(lst2str(data[4:6]), (32, 47), "Battery Design Capacity",
                                        f"{int.from_bytes(data[4:6], 'little') / 10}WH"))
            
        if lst2str(data[6:8]) == "0" * 16:
            self._value.append(metadata(lst2str(data[6:8]), (48, 63), "Battery Last Full Charge Capacity",
                                        "Battery Not Present"))
        elif lst2str(data[6:8]) == "1" * 16:
            self._value.append(metadata(lst2str(data[6:8]), (48, 63), "Battery Last Full Charge Capacity",
                                        "Battery Last Full Charge Capacity Unknown"))
        else:
            self._value.append(metadata(lst2str(data[6:8]), (48, 63), "Battery Last Full Charge Capacity",
                                        f"{int.from_bytes(data[6:8], 'little') / 10}WH"))
        
        self._value.append(metadata(lst2str(data[8:9]), (64, 71), "Battery Type", [
            metadata(lst2str(data[8:9])[7:8], (0, 0), "Invalid Battery Reference", bool(int(lst2str(data[8:9])[7:8]))),
            metadata(lst2str(data[8:9])[0:7], (7, 1), "Reserved")
        ]))


class Get_Manufacturer_Info(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="GMIDB")

        Manufacturer_Info_Target = {
            0: "Port/Cable Plug",
            1: "Battery"
        }

        self._raw = lst2str(data, '>')
        self._value = [
            metadata(lst2str(data[0:1]), (0, 7), "Manufacturer Info Target",
                     Manufacturer_Info_Target.get(data[0:1][0], "Reserved"))
        ]
        
        if data[0:1][0] == 1:
            if 0 <= data[1:2][0] <= 3:
                self._value.append(metadata(lst2str(data[1:2]), (8, 15), "Manufacturer Info Ref",
                                            f"Fixed Battery {data[1:2][0]}"))
            elif 4 <= data[1:2][0] <= 7:
                self._value.append(metadata(lst2str(data[1:2]), (8, 15), "Manufacturer Info Ref",
                                            f"Hot Swappable Battery {data[1:2][0]-4}"))
            else:
                self._value.append(metadata(lst2str(data[1:2]), (8, 15), "Manufacturer Info Ref", "Reserved"))
        else:
            self._value.append(metadata(lst2str(data[1:2]), (8, 15), "Manufacturer Info Ref", "Reserved"))


class Manufacturer_Info(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="MIDB")
        self._raw = lst2str(data, '>')
        data_size = kwargs["ex_header"]["Data Size"].value()
        self._value = [
            metadata(lst2str(data[0:2]), (0, 15), "VID", f"0x{bytes(data[0:2][::-1]).hex().upper()}"),
            metadata(lst2str(data[2:4]), (16, 31), "PID", f"0x{bytes(data[2:4][::-1]).hex().upper()}"),
            metadata(lst2str(data[4:data_size]), (32, data_size*8-1), "Manufacturer String",
                     bytes(data[4:data_size]).decode("ascii"))
        ]


class Security_Request(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="SRQDB")
        self._raw = lst2str(data, '>')
        ex_header = kwargs["ex_header"]
        if ex_header["Request Chunk"].value():
            self._full_raw = self._raw
            self._full_value = None
            return
        
        last_ext = kwargs["last_ext"]
        data_size = ex_header["Data Size"].value()

        if need_ext(ex_header):
            self._full_data = last_ext["SRQDB"]._get_full_data() + data
        else:
            self._full_data = data
        
        self._full_raw = lst2str(self._full_data, '>')
        self._value = "Incomplete Data"

        if len(self._full_data) < data_size:
            self._full_value = "Incomplete Data"
            return
        
        self._full_value = f"0x{bytes(self._full_data[0:data_size]).hex().upper()}"

    def _get_full_data(self) -> list:
        return self._full_data

    def full_raw(self) -> str:
        return self._full_raw
    
    def raw_value(self) -> list:
        return self._value

    def value(self) -> list:
        return self._full_value
    
    def __str__(self) -> str:
        return f"{self._full_value}"
    
    def __repr__(self) -> str:
        return f"{self._field}: {self._full_value}"

    def __getitem__(self, field):
        if self._full_value == "Incomplete Data":
            return None
        if isinstance(field, str):
            return self._field_map.get(field, None)
        else:
            return self._full_value[field]


class Security_Response(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="SRPDB")
        self._raw = lst2str(data, '>')
        ex_header = kwargs["ex_header"]
        if ex_header["Request Chunk"].value():
            self._full_raw = self._raw
            self._full_value = None
            return
        
        last_ext = kwargs["last_ext"]
        data_size = ex_header["Data Size"].value()

        if need_ext(ex_header):
            self._full_data = last_ext["SRPDB"]._get_full_data() + data
        else:
            self._full_data = data
        
        self._full_raw = lst2str(self._full_data, '>')
        self._value = "Incomplete Data"

        if len(self._full_data) < data_size:
            self._full_value = "Incomplete Data"
            return
        
        self._full_value = f"0x{bytes(self._full_data[0:data_size]).hex().upper()}"

    def _get_full_data(self) -> list:
        return self._full_data

    def full_raw(self) -> str:
        return self._full_raw

    def raw_value(self) -> list:
        return self._value

    def value(self) -> list:
        return self._full_value
    
    def __str__(self) -> str:
        return f"{self._full_value}"
    
    def __repr__(self) -> str:
        return f"{self._field}: {self._full_value}"

    def __getitem__(self, field):
        if self._full_value == "Incomplete Data":
            return None
        if isinstance(field, str):
            return self._field_map.get(field, None)
        else:
            return self._full_value[field]


class Firmware_Update_Request(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="FRQDB")
        self._raw = lst2str(data, '>')
        ex_header = kwargs["ex_header"]
        if ex_header["Request Chunk"].value():
            self._full_raw = self._raw
            self._full_value = None
            return
        
        last_ext = kwargs["last_ext"]
        data_size = ex_header["Data Size"].value()

        if need_ext(ex_header):
            self._full_data = last_ext["FRQDB"]._get_full_data() + data
        else:
            self._full_data = data
        
        self._full_raw = lst2str(self._full_data, '>')
        self._value = "Incomplete Data"

        if len(self._full_data) < data_size:
            self._full_value = "Incomplete Data"
            return
        
        self._full_value = f"0x{bytes(self._full_data[0:data_size]).hex().upper()}"

    def _get_full_data(self) -> list:
        return self._full_data

    def full_raw(self) -> str:
        return self._full_raw

    def raw_value(self) -> list:
        return self._value

    def value(self) -> list:
        return self._full_value
    
    def __str__(self) -> str:
        return f"{self._full_value}"
    
    def __repr__(self) -> str:
        return f"{self._field}: {self._full_value}"

    def __getitem__(self, field):
        if self._full_value == "Incomplete Data":
            return None
        if isinstance(field, str):
            return self._field_map.get(field, None)
        else:
            return self._full_value[field]


class Firmware_Update_Response(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="FRPDB")
        self._raw = lst2str(data, '>')
        ex_header = kwargs["ex_header"]
        if ex_header["Request Chunk"].value():
            self._full_raw = self._raw
            self._full_value = None
            return
        
        last_ext = kwargs["last_ext"]
        data_size = ex_header["Data Size"].value()

        if need_ext(ex_header):
            self._full_data = last_ext["FRPDB"]._get_full_data() + data
        else:
            self._full_data = data
        
        self._full_raw = lst2str(self._full_data, '>')
        self._value = "Incomplete Data"

        if len(self._full_data) < data_size:
            self._full_value = "Incomplete Data"
            return
        
        self._full_value = f"0x{bytes(self._full_data[0:data_size]).hex().upper()}"

    def _get_full_data(self) -> list:
        return self._full_data

    def full_raw(self) -> str:
        return self._full_raw

    def raw_value(self) -> list:
        return self._value

    def value(self) -> list:
        return self._full_value
    
    def __str__(self) -> str:
        return f"{self._full_value}"
    
    def __repr__(self) -> str:
        return f"{self._field}: {self._full_value}"

    def __getitem__(self, field):
        if self._full_value == "Incomplete Data":
            return None
        if isinstance(field, str):
            return self._field_map.get(field, None)
        else:
            return self._full_value[field]


class PPS_Status(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="PPSSDB")

        PTF = {
            "00": "Not Support",
            "01": "Normal",
            "10": "Warning",
            "11": "Over Temperature"
        }

        self._raw = lst2str(data, '>')
        self._value = []

        if lst2str(data[0:2]) == "1" * 16:
            self._value.append(metadata(lst2str(data[0:2]), (0, 15), "Output Voltage", "Not Support"))
        else:
            self._value.append(metadata(lst2str(data[0:2]), (0, 15), "Output Voltage",
                                        f"{int(lst2str(data[0:2]), 2) / 50}mV"))
        
        if lst2str(data[2:3]) == "1" * 8:
            self._value.append(metadata(lst2str(data[2:3]), (16, 23), "Output Current", "Not Support"))
        else:
            self._value.append(metadata(lst2str(data[2:3]), (16, 23), "Output Current",
                                        f"{int(lst2str(data[2:3]), 2) / 20}mA"))
        
        RTF_raw = lst2str(data[3:4])
        Real_Time_Flags = [
            metadata(RTF_raw[7:8], (0, 0), "Reserved"),
            metadata(RTF_raw[5:7], (2, 1), "PTF", PTF.get(RTF_raw[5:7], "Reserved")),
            metadata(RTF_raw[4:5], (3, 3), "OMF", bool(int(RTF_raw[4:5]))),
            metadata(RTF_raw[0:4], (7, 4), "Reserved")
        ]
        self._value.append(metadata(RTF_raw, (24, 31), "Real Time Flags", Real_Time_Flags))


class Country_Info(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="CIDB")
        self._raw = lst2str(data, '>')
        data_size = kwargs["ex_header"]["Data Size"].value()
        self._value = [
            metadata(lst2str(data[0:2]), (0, 15), "Country Code", bytes(data[0:2]).decode("ascii")),
            metadata(lst2str(data[2:4]), (16, 31), "Reserved"),
            metadata(lst2str(data[4:data_size]), (32, data_size*8-1), "Country Specific Data",
                     bytes(data[4:data_size]).decode("ascii"))
        ]


class Country_Codes(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="CCDB")
        self._raw = lst2str(data, '>')
        data_size = kwargs["ex_header"]["Data Size"].value()
        self._value = [
            metadata(lst2str(data[0:1]), (0, 7), "Length", data[0:1][0]),
            metadata(lst2str(data[1:2]), (8, 15), "Reserved")
        ]

        for i in range(1, data_size/2):
            metadata(lst2str(data[i*2:(i+1)*2], (i*16, (i+1)*16-1)), f"Country Code {i}",
                     bytes(data[i*2:(i+1)*2]).decode("ascii"))


class Sink_Capabilities_Extended(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="SKEDB")

        Load_Step = {
            "00": "150mA/μs",
            "01": "500mA/μs"
        }

        Touch_Temp = {
            0: "Not Applicable",
            1: "[IEC 60950-1]",
            2: "[IEC 62368-1] TS1",
            3: "[IEC 62368-1] TS2"
        }

        self._raw = lst2str(data, '>')
        self._value = [
            metadata(lst2str(data[0:2]), (0, 15), "VID", f"0x{bytes(data[0:2][::-1]).hex().upper()}"),
            metadata(lst2str(data[2:4]), (16, 31), "PID", f"0x{bytes(data[2:4][::-1]).hex().upper()}"),
            metadata(lst2str(data[4:8]), (32, 63), "XID", f"0x{bytes(data[0:2][::-1]).hex().upper()}"),
            metadata(lst2str(data[8:9]), (64, 71), "FW Version", f"0x{bytes(data[8:9][::-1]).hex().upper()}"),
            metadata(lst2str(data[9:10]), (72, 79), "HW Version", f"0x{bytes(data[9:10][::-1]).hex().upper()}"),
            metadata(lst2str(data[10:11]), (80, 87), "SKEDB Version",
                     "Version 1.0" if data[10:11][0] == 1 else "Reserved"),
            metadata(lst2str(data[11:12]), (88, 95), "Load Step",
                     Load_Step.get(lst2str(data[11:12])[6:8], "Reserved"))
        ]

        SLC_raw = lst2str(data[12:14])
        Sink_Load_Characteristics = [
            metadata(SLC_raw[11:16], (4, 0), "Percent overload", f"{min(25, int(SLC_raw[11:16], 2)) * 10}%"),
            metadata(SLC_raw[5:11], (10, 5), "Overload period", f"{int(SLC_raw[5:11], 2) * 20}ms"),
            metadata(SLC_raw[1:5], (14, 11), "Duty cycle", f"{int(SLC_raw[1:5], 2) * 5}%"),
            metadata(SLC_raw[0:1], (15, 15), "VBUS Droop", bool(int(SLC_raw[0:1])))
        ]
        self._value.append(metadata(SLC_raw, (96, 111), "Sink Load Characteristics", Sink_Load_Characteristics))

        Compliance_raw = lst2str(data[14:15])
        Compliance = [
            metadata(Compliance_raw[7:8], (0, 0), "Requires LPS Source", bool(int(Compliance_raw[7:8]))),
            metadata(Compliance_raw[6:7], (1, 1), "Requires PS1 Source", bool(int(Compliance_raw[6:7]))),
            metadata(Compliance_raw[5:6], (2, 2), "Requires PS2 Source", bool(int(Compliance_raw[5:6]))),
            metadata(Compliance_raw[0:5], (7, 3), "Reserved")
        ]
        self._value.append(metadata(Compliance_raw, (112, 119), "Compliance", Compliance))

        self._value.append(metadata(lst2str(data[15:16]), (120, 127), "Touch Temp",
                           Touch_Temp.get(data[15:16][0], "Reserved")))

        BF_raw = lst2str(data[16:17])
        Battery_Info = [
            metadata(BF_raw[0:4], (7, 4), "Hot Swappable Battery", BF_raw[0:4]),
            metadata(BF_raw[4:8], (3, 0), "Fixed Batteries", BF_raw[4:8])
        ]
        self._value.append(metadata(BF_raw, (128, 135), "Battery Info", Battery_Info))

        SM_raw = lst2str(data[17:18])
        Sink_Modes = [
            metadata(SM_raw[7:8], (0, 0), "PPS charging supported", bool(int(SM_raw[7:8]))),
            metadata(SM_raw[6:7], (1, 1), "VBUS powered", bool(int(SM_raw[6:7]))),
            metadata(SM_raw[5:6], (2, 2), "AC Supply powered", bool(int(SM_raw[5:6]))),
            metadata(SM_raw[4:5], (3, 3), "Battery powered", bool(int(SM_raw[4:5]))),
            metadata(SM_raw[3:4], (4, 4), "Battery essentially unlimited", bool(int(SM_raw[3:4]))),
            metadata(SM_raw[2:3], (5, 5), "AVS Support", bool(int(SM_raw[2:3]))),
            metadata(SM_raw[0:2], (7, 6), "Reserved")
        ]

        self._value.extend([
            metadata(SM_raw, (136, 143), "Sink Modes", Sink_Modes),
            metadata(lst2str(data[18:19]), (144, 151), "SPR Sink Minimum PDP",
                     f"{int(lst2str(data[18:19])[1:8], 2)}W"),
            metadata(lst2str(data[19:20]), (152, 159), "SPR Sink Operational PDP",
                     f"{int(lst2str(data[19:20])[1:8], 2)}W"),
            metadata(lst2str(data[20:21]), (160, 167), "SPR Sink Maximum PDP",
                     f"{int(lst2str(data[20:21])[1:8], 2)}W"),
            metadata(lst2str(data[21:22]), (168, 175), "EPR Sink Minimum PDP",
                     f"{int(lst2str(data[21:22]), 2)}W"),
            metadata(lst2str(data[22:23]), (176, 183), "EPR Sink Operational PDP",
                     f"{int(lst2str(data[22:23]), 2)}W"),
            metadata(lst2str(data[23:24]), (184, 191), "EPR Sink Maximum PDP",
                     f"{int(lst2str(data[23:24]), 2)}W")
        ])


class Extended_Control(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="ECDB")
        self._raw = lst2str(data, '>')

        EPR_Type = {
            1: "EPR_Get_Source_Cap",
            2: "EPR_Get_Sink_Cap",
            3: "EPR_KeepAlive",
            4: "EPR_KeepAlive_Ack"
        }

        self._value = [
            metadata(lst2str(data[0:1]), (0, 7), "Type", EPR_Type.get(data[0:1][0], "Reserved")),
            metadata(lst2str(data[1:2]), (8, 15), "Data", f"0x{bytes(data[1:2]).hex().upper()}")
        ]


class EPR_Source_Capabilities(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')
        num_objs = kwargs["header"][1].value()
        ex_header = kwargs["ex_header"]
        if ex_header["Request Chunk"].value():
            self._full_raw = self._raw
            self._full_value = None
            return
        
        last_ext = kwargs["last_ext"]
        data_size = ex_header["Data Size"].value()

        if need_ext(ex_header):
            self._full_data = last_ext["Data Block"]._get_full_data() + data
            self._full_num_objs = last_ext["Data Block"]._get_full_num_objs() + num_objs - 0.5
        else:
            self._full_data = data
            self._full_num_objs = num_objs - 0.5
        
        self._full_raw = lst2str(self._full_data, '>')
        self._value = "Incomplete Data"

        if len(self._full_data) < data_size:
            self._full_value = "Incomplete Data"
            return
        
        self._full_value = []
        for i in range(int(self._full_num_objs)):
            sub_raw = lst2str(self._full_data[i*4:(i+1)*4])
            if sub_raw == "0" * 32:
                self._full_value.append(metadata(sub_raw, (i*32, (i+1)*32-1), f"PDO {i+1}", "Empty PDO"))
            else:
                self._full_value.append(pdo_type(sub_raw)(sub_raw, (i*32, (i+1)*32-1), f"PDO {i+1}"))

        self._field_map = {m.field(): m for m in self._full_value}
        if "Reserved" in self._field_map:
            del self._field_map["Reserved"]

    def _get_full_data(self) -> list:
        return self._full_data

    def _get_full_num_objs(self) -> float:
        return self._full_num_objs

    def full_raw(self) -> str:
        return self._full_raw

    def raw_value(self) -> list:
        return self._value

    def value(self) -> list:
        return self._full_value
    
    def __str__(self) -> str:
        return f"{self._full_value}"
    
    def __repr__(self) -> str:
        return f"{self._field}: {self._full_value}"

    def __getitem__(self, field):
        if self._full_value == "Incomplete Data":
            return None
        if isinstance(field, str):
            return self._field_map.get(field, None)
        else:
            return self._full_value[field]


class EPR_Sink_Capabilities(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')
        num_objs = kwargs["header"][1].value()
        ex_header = kwargs["ex_header"]
        if ex_header["Request Chunk"].value():
            self._full_raw = self._raw
            self._full_value = None
            return
        
        last_ext = kwargs["last_ext"]
        data_size = ex_header["Data Size"].value()

        if need_ext(ex_header):
            self._full_data = last_ext["Data Block"]._get_full_data() + data
            self._full_num_objs = last_ext["Data Block"]._get_full_num_objs() + num_objs - 0.5
        else:
            self._full_data = data
            self._full_num_objs = num_objs - 0.5
        
        self._full_raw = lst2str(self._full_data, '>')
        self._value = "Incomplete Data"

        if len(self._full_data) < data_size:
            self._full_value = "Incomplete Data"
            return
        
        self._full_value = []
        for i in range(int(self._full_num_objs)):
            sub_raw = lst2str(self._full_data[i*4:(i+1)*4])
            if sub_raw == "0" * 32:
                self._full_value.append(metadata(sub_raw, (i*32, (i+1)*32-1), f"PDO {i+1}", "Empty PDO"))
            else:
                self._full_value.append(sink_pdo_type(sub_raw)(sub_raw, (i*32, (i+1)*32-1), f"PDO {i+1}"))

        self._field_map = {m.field(): m for m in self._full_value}
        if "Reserved" in self._field_map:
            del self._field_map["Reserved"]

    def _get_full_data(self) -> list:
        return self._full_data

    def _get_full_num_objs(self) -> float:
        return self._full_num_objs

    def full_raw(self) -> str:
        return self._full_raw

    def raw_value(self) -> list:
        return self._value

    def value(self) -> list:
        return self._full_value
    
    def __str__(self) -> str:
        return f"{self._full_value}"
    
    def __repr__(self) -> str:
        return f"{self._field}: {self._full_value}"

    def __getitem__(self, field):
        if self._full_value == "Incomplete Data":
            return None
        if isinstance(field, str):
            return self._field_map.get(field, None)
        else:
            return self._full_value[field]


class Vendor_Defined_Extended(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')
        ex_header = kwargs["ex_header"]
        if ex_header["Request Chunk"].value():
            self._full_raw = self._raw
            self._full_value = None
            return
        
        last_ext = kwargs["last_ext"]
        data_size = ex_header["Data Size"].value()

        if need_ext(ex_header):
            self._full_data = last_ext["Data Block"]._get_full_data() + data
        else:
            self._full_data = data
        
        self._full_raw = lst2str(self._full_data, '>')
        self._value = "Incomplete Data"

        if len(self._full_data) < data_size:
            self._full_value = "Incomplete Data"
            return
        
        self._full_value = [
            VDM_header(lst2str(self._full_data[0:4]), (0, 31)),
            metadata(lst2str(self._full_data[4:data_size]), (32, data_size*8-1), "VDEDB",
                     f"0x{bytes(self._full_data[4:data_size]).hex().upper()}")
        ]

    def _get_full_data(self) -> list:
        return self._full_data

    def full_raw(self) -> str:
        return self._full_raw

    def raw_value(self) -> list:
        return self._value

    def value(self) -> list:
        return self._full_value
    
    def __str__(self) -> str:
        return f"{self._full_value}"
    
    def __repr__(self) -> str:
        return f"{self._field}: {self._full_value}"

    def __getitem__(self, field):
        if self._full_value == "Incomplete Data":
            return None
        if isinstance(field, str):
            return self._field_map.get(field, None)
        else:
            return self._full_value[field]


class Reserved(metadata):
    def __init__(self, data: list, bit_loc: tuple, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')
        self._value = f"0x{bytes(data).hex().upper()}"


class pd_msg(metadata):
    def __init__(self,
                 data: list,
                 last_pdo: metadata = None,
                 last_ext: metadata = None,
                 last_rdo: metadata = None):
        super().__init__(field="pd")
        end_of_msg = data[1] + 2
        self._raw = lst2str(data[0:end_of_msg], '>')
        self._bit_loc = (0, (end_of_msg) * 8 - 1)

        SOP = {
            224: "SOP",
            192: "SOP'",
            160: "SOP''",
            128: "SOP'_DEBUG",
            96: "SOP''_DEBUG",
        }

        try:
            self._value = [
                metadata(lst2str(data[1:2]), (8, 15), "Length", data[1:2][0]),
                metadata(lst2str(data[2:3]), (16, 23), "SOP*", SOP[data[2:3][0]]),
                msg_header(lst2str(data[3:5]), (24, 39), SOP[data[2:3][0]])
            ]

            end_of_msg = 5 + self._value[2][1].value() * 4

            if self._value[2]["Extended"].value():
                self._value.append(ex_msg_header(lst2str(data[5:7]), (40, 55)))
                self._value.append(globals()[self._value[2]["Message Type"].value()](data[7:end_of_msg],
                                                                                (56, (end_of_msg)*8-1),
                                                                                sop=SOP[data[2:3][0]],
                                                                                header=self._value[2],
                                                                                ex_header=self._value[3],
                                                                                last_pdo=last_pdo,
                                                                                last_ext=last_ext,
                                                                                last_rdo=last_rdo))
            else:
                if self._value[2]["Message Type"].value() in globals():
                    self._value.append(globals()[self._value[2]["Message Type"].value()](data[5:end_of_msg],
                                                                                    (40, (end_of_msg)*8-1),
                                                                                    sop=SOP[data[2:3][0]],
                                                                                    header=self._value[2],
                                                                                    last_pdo=last_pdo))
        except Exception as e:
            self._value = [
                metadata(lst2str(data[1:2]), (8, 15), "Length", data[1]),
                metadata(lst2str(data[2:3]), (16, 23), "SOP*", SOP[data[2]]),
                metadata(lst2str(data[3:data[1] + 2]), (24, (end_of_msg) * 8 - 1), "Error Data",
                         f"0x{bytes(data[0:end_of_msg]).hex().upper()}")
            ]
            if __flag__:
                raise(e)


class WITRN_DEV:
    def __init__(self, **kwargs):
        global __flag__
        __flag__ = kwargs.get("debug", False)
        self.data = None
        self.timestamp = None
        self.last_pdo = None
        self.last_ext = None
        self.last_rdo = None

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
        self.timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.data = self.dev.read(64)
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
        if data is None:
            if self.data is None:
                raise ValueError("No data available to unpack")
            elif len(self.data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            msg = pd_msg(self.data, self.last_pdo, self.last_ext, self.last_rdo)
            if msg[2].field() == "Error Data":
                return self.timestamp, msg
            if is_pdo(msg):
                self.last_pdo = msg
            if provide_ext(msg):
                self.last_ext = msg
            if is_rdo(msg):
                self.last_rdo = msg
            return self.timestamp, msg
        else:
            if len(data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            return timestamp, pd_msg(data, last_pdo, last_ext, last_rdo)

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

# End of File