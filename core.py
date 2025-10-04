import hid
import struct
import time
from datetime import timedelta

K2_TARGET_VID = 0x0716
K2_TARGET_PID = 0x5060

SOP = {
    224: "SOP",
    192: "SOP'",
    160: "SOP''",
    128: "SOP'_DEBUG",
    96: "SOP''_DEBUG",
}


REV = {
    "00": "Rev 1.0",
    "01": "Rev 2.0",
    "10": "Rev 3.x",
    "11": "Reserved",
}


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


PEAK_CURRENT = {
    "00":"Not Support",
    "01": f"1. Peak current equals 150% IoC for 1ms @ 5% duty cycle (low current equals 97% IoC for 19ms)\n"
          f"2. Peak current equals 125% IoC for 2ms @ 10% duty cycle (low current equals 97% IoC for 18ms)\n"
          f"3. Peak current equals 110% IoC for 10ms @ 50% duty cycle (low current equals 90% IoC for 10ms)",
    "10": f"1. Peak current equals 200% IoC for 1ms @ 5% duty cycle (low current equals 95% IoC for 19ms)\n"
          f"2. Peak current equals 150% IoC for 2ms @ 10% duty cycle (low current equals 94% IoC for 18ms)\n"
          f"3. Peak current equals 125% IoC for 10ms @ 50% duty cycle (low current equals 75% IoC for 10ms)",
    "11": f"1. Peak current equals 200% IoC for 1ms @ 5% duty cycle (low current equals 95% IoC for 19ms)\n"
          f"2. Peak current equals 175% IoC for 2ms @ 10% duty cycle (low current equals 92% IoC for 18ms)\n"
          f"3. Peak current equals 150% IoC for 10ms @ 50% duty cycle (low current equals 50% IoC for 10ms)"
}


def lst2str(lst: list, order: str='<') -> str:
    if order == '>':
        return ''.join(f'{x:08b}' for x in bytes(lst))
    elif order == '<':
        return ''.join(f'{x:08b}' for x in bytes(lst)[::-1])
    else:
        raise ValueError("Order must be '>' or '<'")


class metadata:
    def __init__(self, raw=None, bit_loc=None, field=None, value=None):
        self._raw = raw
        self._bit_loc = bit_loc
        self._field = field
        self._value = value
    
    def raw(self):
        return self._raw
    
    def bit_loc(self):
        return self._bit_loc
    
    def field(self):
        return self._field
    
    def value(self):
        return self._value

    def __str__(self):
        return f"{self._value}"
    
    def __repr__(self):
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
                     f"{struct.unpack('<f', bytes(data[42:46]))[0]}℃"),
            metadata(lst2str(data[46:50]), (368, 399), "VBus",
                     f"{struct.unpack('<f', bytes(data[46:50]))[0]}V"),
            metadata(lst2str(data[50:54]), (400, 431), "Current",
                     f"{struct.unpack('<f', bytes(data[50:54]))[0]}A"),
            metadata(lst2str([data[54]]), (432, 439), "Group", f"{data[54] + 1}"),
            metadata(lst2str([data[55]]), (440, 447), "CC1", f"{data[55] / 10}V"),
            metadata(lst2str([data[56]]), (448, 455), "CC2", f"{data[56] / 10}V"),
        ]


class msg_header(metadata):
    def __init__(self, raw: str, bit_loc: tuple, sop: str):
        super().__init__(raw, bit_loc, "Message Header")
        self._value = [
            metadata(raw[0], 15, "Extended", bool(int(raw[0]))),
            metadata(raw[1:4], (14, 12), "Number of Data Objects", int(raw[1:4], 2)),
            metadata(raw[4:7], (11, 9), "MessageID", int(raw[4:7], 2)),
        ]

        if sop == "SOP":
            self._value.append(metadata(raw[7], 8, "Port Power Role",
                                       "Sink" if raw[7] == '0' else "Source"))
        elif sop in ["SOP'", "SOP''"]:
            self._value.append(metadata(raw[7], 8, "Cable Plug",
                                       "DFP or UFP" if raw[7] == '0' else "Cable Plug or VPD"))

        self._value.append(metadata(raw[8:10], (7, 6), "Specification Revision",
                                   REV[raw[8:10]]))

        if sop == "SOP":
            self._value.append(metadata(raw[10], 5, "Port Data Role",
                                       "UFP" if raw[10] == '0' else "DFP"))
        elif sop in ["SOP'", "SOP''"]:
            self._value.append(metadata(raw[10], 5, "Reserved"))
        
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
    type = msg["Message Header"]["Message Type"].value()
    return type in ["Source_Capabilities", "EPR_Source_Capabilities",]


class ex_msg_header(metadata):
    def __init__(self, raw: str, bit_loc: tuple):
        super().__init__(raw, bit_loc, "Extended Message Header")
        self._value = [
            metadata(raw[0], 15, "Chunked", bool(int(raw[0]))),
            metadata(raw[1:5], (14, 11), "Chunk Number", int(raw[1:5], 2)),
            metadata(raw[5], 10, "Request Chunk", bool(int(raw[5]))),
            metadata(raw[6], 9, "Reserved"),
            metadata(raw[7:16], (8, 0), "Data Size", int(raw[7:16], 2)),
        ]


class FPDO(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "FPDO"),
            metadata(raw[2], 29, "Dual-Role Power", bool(int(raw[2]))),
            metadata(raw[3], 28, "USB Suspend Supported", bool(int(raw[3]))),
            metadata(raw[4], 27, "Unconstrained Power", bool(int(raw[4]))),
            metadata(raw[5], 26, "USB Communications Capable", bool(int(raw[5]))),
            metadata(raw[6], 25, "Dual-Role Data", bool(int(raw[6]))),
            metadata(raw[7], 24, "Unchunked Extended Messages Supported", bool(int(raw[7]))),
            metadata(raw[8], 23, "EPR Capable", bool(int(raw[8]))),
            metadata(raw[9], 22, "Reserved"),
            metadata(raw[10:12], (21, 20), "Peak Current", raw[10:12]),
            metadata(raw[12:22], (19, 10), "Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Maximum Current", f"{int(raw[22:32], 2) / 100}A")
        ]


class FPDO_S(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "FPDO Sink"),
            metadata(raw[2], 29, "Dual-Role Power", bool(int(raw[2]))),
            metadata(raw[3], 28, "Higher Capability", bool(int(raw[3]))),
            metadata(raw[4], 27, "Unconstrained Power", bool(int(raw[4]))),
            metadata(raw[5], 26, "USB Communications Capable", bool(int(raw[5]))),
            metadata(raw[6], 25, "Dual-Role Data", bool(int(raw[6]))),
        ]

        if raw[6:8] == "00":
            self._value.append(metadata(raw[7:9], (24, 23),
                                        "Fast Role Swap required USB Type-C Current",
                                        "Not Supported"))
        elif raw[6:8] == "01":
            self._value.append(metadata(raw[7:9], (24, 23),
                                        "Fast Role Swap required USB Type-C Current",
                                        "Default USB Port"))
        elif raw[6:8] == "10":
            self._value.append(metadata(raw[7:9], (24, 23),
                                        "Fast Role Swap required USB Type-C Current",
                                        "1.5A@5V"))
        elif raw[6:8] == "11":
            self._value.append(metadata(raw[7:9], (24, 23),
                                        "Fast Role Swap required USB Type-C Current",
                                        "3A@5V"))
        
        self._value.append(metadata(raw[9:12], (22, 20), "Reserved"))
        self._value.append(metadata(raw[12:22], (19, 10), "Voltage", f"{int(raw[12:22], 2) / 20}V"))
        self._value.append(metadata(raw[22:32], (9, 0), "Operational Current", f"{int(raw[22:32], 2) / 100}A"))


class BPDO(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "BPDO"),
            metadata(raw[2:12], (29, 20), "Maximum Voltage", f"{int(raw[2:12], 2) / 20}V"),
            metadata(raw[12:22], (19, 10), "Minimum Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Maximum Allowable Power", f"{int(raw[22:32], 2) / 4}W")
        ]


class BPDO_S(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "BPDO Sink"),
            metadata(raw[2:12], (29, 20), "Maximum Voltage", f"{int(raw[2:12], 2) / 20}V"),
            metadata(raw[12:22], (19, 10), "Minimum Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Operational Power", f"{int(raw[22:32], 2) / 4}W")
        ]


class VPDO(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "VPDO"),
            metadata(raw[2:12], (29, 20), "Maximum Voltage", f"{int(raw[2:12], 2) / 20}V"),
            metadata(raw[12:22], (19, 10), "Minimum Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Maximum Current", f"{int(raw[22:32], 2) / 100}A")
        ]


class VPDO_S(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "VPDO Sink"),
            metadata(raw[2:12], (29, 20), "Maximum Voltage", f"{int(raw[2:12], 2) / 20}V"),
            metadata(raw[12:22], (19, 10), "Minimum Voltage", f"{int(raw[12:22], 2) / 20}V"),
            metadata(raw[22:32], (9, 0), "Operational Current", f"{int(raw[22:32], 2) / 100}A")
        ]


class PPS_PDO(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO"),
            metadata(raw[2:4], (29, 28), "APDO Type", "SPR PPS"),
            metadata(raw[4], 27, "PPS Power Limited", bool(int(raw[4]))),
            metadata(raw[5:7], (26, 25), "Reserved"),
            metadata(raw[7:15], (24, 17), "Maximum Voltage", f"{int(raw[7:15], 2) / 10}V"),
            metadata(raw[15], 16, "Reserved"),
            metadata(raw[16:24], (15, 8), "Minimum Voltage", f"{int(raw[16:24], 2) / 10}V"),
            metadata(raw[24], 7, "Reserved"),
            metadata(raw[25:32], (6, 0), "Maximum Current", f"{int(raw[25:32], 2) / 20}A"),
        ]


class PPS_PDO_S(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO Sink"),
            metadata(raw[2:4], (29, 28), "APDO Type", "SPR PPS"),
            metadata(raw[4:7], (27, 25), "Reserved"),
            metadata(raw[7:15], (24, 17), "Maximum Voltage", f"{int(raw[7:15], 2) / 10}V"),
            metadata(raw[15], 16, "Reserved"),
            metadata(raw[16:24], (15, 8), "Minimum Voltage", f"{int(raw[16:24], 2) / 10}V"),
            metadata(raw[24], 7, "Reserved"),
            metadata(raw[25:32], (6, 0), "Maximum Current", f"{int(raw[25:32], 2) / 20}A"),
        ]


class EPR_AVS_PDO(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO"),
            metadata(raw[2:4], (29, 28), "APDO Type", "EPR AVS"),
            metadata(raw[4:6], (27, 26), "Peak Current", raw[4:6]),
            metadata(raw[6:15], (25, 17), "Maximum Voltage", f"{int(raw[6:15], 2) / 10}V"),
            metadata(raw[15], 16, "Reserved"),
            metadata(raw[16:24], (15, 8), "Minimum Voltage", f"{int(raw[16:24], 2) / 10}V"),
            metadata(raw[24:32], (7, 0), "PDP", f"{int(raw[24:32], 2)}W"),
        ]


class EPR_AVS_PDO_S(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO Sink"),
            metadata(raw[2:4], (29, 28), "APDO Type", "EPR AVS"),
            metadata(raw[4:6], (27, 26), "Reserved"),
            metadata(raw[6:15], (25, 17), "Maximum Voltage", f"{int(raw[6:15], 2) / 10}V"),
            metadata(raw[15], 16, "Reserved"),
            metadata(raw[16:24], (15, 8), "Minimum Voltage", f"{int(raw[16:24], 2) / 10}V"),
            metadata(raw[24:32], (7, 0), "PDP", f"{int(raw[24:32], 2)}W"),
        ]


class SPR_AVS_PDO(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO"),
            metadata(raw[2:4], (29, 28), "APDO Type", "SPR AVS"),
            metadata(raw[4:6], (27, 26), "Peak Current", raw[4:6]),
            metadata(raw[6:12], (25, 20), "Reserved"),
            metadata(raw[12:22], (19, 10), "Maximum Current 15V", f"{int(raw[12:22], 2) / 100}A"),
            metadata(raw[22:32], (9, 0), "Maximum Current 20V", f"{int(raw[22:32], 2) / 100}A"),
        ]


class SPR_AVS_PDO_S(metadata):
    def __init__(self, raw, bit_loc, field):
        super().__init__(raw, bit_loc, field)
        self._value = [
            metadata(raw[0:2], (31, 30), "Supply Type", "APDO Sink"),
            metadata(raw[2:4], (29, 28), "APDO Type", "SPR AVS"),
            metadata(raw[4:12], (27, 20), "Reserved"),
            metadata(raw[12:22], (19, 10), "Maximum Current 15V", f"{int(raw[12:22], 2) / 100}A"),
            metadata(raw[22:32], (9, 0), "Maximum Current 20V", f"{int(raw[22:32], 2) / 100}A"),
        ]


class F_VRDO(metadata):
    def __init__(self, raw, bit_loc, field, **kwargs):
        super().__init__(raw, bit_loc, field)
        self._pdo = kwargs["pdo"]
        self._value = [
            metadata(raw[0:4], (31, 28), "Object Position", int(raw[0:4], 2)),
            metadata(raw[4], 27, "Giveback", bool(int(raw[4]))),
            metadata(raw[5], 26, "Capability Mismatch", bool(int(raw[5]))),
            metadata(raw[6], 25, "USB Communications Capable", bool(int(raw[6]))),
            metadata(raw[7], 24, "No USB Suspend", bool(int(raw[7]))),
            metadata(raw[8], 23, "Unchunked Extended Messages Supported", bool(int(raw[8]))),
            metadata(raw[9], 22, "EPR Capable", bool(int(raw[9]))),
            metadata(raw[10:12], (21, 20), "Reserved"),
            metadata(raw[12:22], (19, 10), "Operating Current", f"{int(raw[12:22], 2) / 100}A"),
            metadata(raw[22:32], (9, 0), "Maximum Operating Current", f"{int(raw[22:32], 2) / 100}A"),
        ]

    def pdo(self) -> metadata:
        return self._pdo


class BRDO(metadata):
    def __init__(self, raw, bit_loc, field, **kwargs):
        super().__init__(raw, bit_loc, field)
        self._pdo = kwargs["pdo"]
        self._value = [
            metadata(raw[0:4], (31, 28), "Object Position", int(raw[0:4], 2)),
            metadata(raw[4], 27, "Giveback", bool(int(raw[4]))),
            metadata(raw[5], 26, "Capability Mismatch", bool(int(raw[5]))),
            metadata(raw[6], 25, "USB Communications Capable", bool(int(raw[6]))),
            metadata(raw[7], 24, "No USB Suspend", bool(int(raw[7]))),
            metadata(raw[8], 23, "Unchunked Extended Messages Supported", bool(int(raw[8]))),
            metadata(raw[9], 22, "EPR Capable", bool(int(raw[9]))),
            metadata(raw[10:12], (21, 20), "Reserved"),
            metadata(raw[12:22], (19, 10), "Operating Power", f"{int(raw[12:22], 2) / 4}W"),
            metadata(raw[22:32], (9, 0), "Maximum Operating Power", f"{int(raw[22:32], 2) / 4}W"),
        ]
    
    def pdo(self) -> metadata:
        return self._pdo


class PPS_RDO(metadata):
    def __init__(self, raw, bit_loc, field, **kwargs):
        super().__init__(raw, bit_loc, field)
        self._pdo = kwargs["pdo"]
        self._value = [
            metadata(raw[0:4], (31, 28), "Object Position", int(raw[0:4], 2)),
            metadata(raw[4], 27, "Reserved"),
            metadata(raw[5], 26, "Capability Mismatch", bool(int(raw[5]))),
            metadata(raw[6], 25, "USB Communications Capable", bool(int(raw[6]))),
            metadata(raw[7], 24, "No USB Suspend", bool(int(raw[7]))),
            metadata(raw[8], 23, "Unchunked Extended Messages Supported", bool(int(raw[8]))),
            metadata(raw[9], 22, "EPR Capable", bool(int(raw[9]))),
            metadata(raw[10], 21, "Reserved"),
            metadata(raw[11:23], (20, 9), "Output Voltage", f"{int(raw[11:23], 2) / 50}V"),
            metadata(raw[23:25], (8, 7), "Reserved"),
            metadata(raw[25:32], (6, 0), "Operating Current", f"{int(raw[25:32], 2) / 20}A"),
        ]
    
    def pdo(self) -> metadata:
        return self._pdo


class AVS_RDO(metadata):
    def __init__(self, raw, bit_loc, field, **kwargs):
        super().__init__(raw, bit_loc, field)
        self._pdo = kwargs["pdo"]
        self._value = [
            metadata(raw[0:4], (31, 28), "Object Position", int(raw[0:4], 2)),
            metadata(raw[4], 27, "Reserved"),
            metadata(raw[5], 26, "Capability Mismatch", bool(int(raw[5]))),
            metadata(raw[6], 25, "USB Communications Capable", bool(int(raw[6]))),
            metadata(raw[7], 24, "No USB Suspend", bool(int(raw[7]))),
            metadata(raw[8], 23, "Unchunked Extended Messages Supported", bool(int(raw[8]))),
            metadata(raw[9], 22, "EPR Capable", bool(int(raw[9]))),
            metadata(raw[10], 21, "Reserved"),
            metadata(raw[11:23], (20, 9), "Output Voltage", f"{int(raw[11:23], 2) / 40}V"),
            metadata(raw[23:25], (8, 7), "Reserved"),
            metadata(raw[25:32], (6, 0), "Operating Current", f"{int(raw[25:32], 2) / 20}A"),
        ]
    
    def pdo(self) -> metadata:
        return self._pdo


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
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        num_objs = kwargs["header"][1].value()
        self._value = []
        for i in range(num_objs):
            sub_raw = lst2str(data[i*4:(i+1)*4])
            self._value.append(pdo_type(sub_raw)(sub_raw, (i*32, (i+1)*32-1), f"PDO {i+1}"))


class Request(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        self._value = []
        pdo_list = kwargs["last_pdo"]["Data Objects"].value()
        sub_raw = lst2str(data[0:4])
        pdo = pdo_list[int(sub_raw[0:4], 2) - 1]
        self._value.append(rdo_type(pdo)(sub_raw, (0, 31), "RDO", pdo=pdo))


class BIST(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        num_objs = kwargs["header"][1].value()
        sub_raw = lst2str(data[0:4])
        BIST_Data_Object = []
        if sub_raw[0:4] == "0101":
            BIST_Data_Object.append(metadata(sub_raw[0:4], (31, 28), "BIST Mode", "BIST Carrier Mode"))
        elif sub_raw[0:4] == "1000":
            BIST_Data_Object.append(metadata(sub_raw[0:4], (31, 28), "BIST Mode", "BIST Test Data"))
        elif sub_raw[0:4] == "1001":
            BIST_Data_Object.append(metadata(sub_raw[0:4], (31, 28), "BIST Mode", "BIST Shared Test Mode Entry"))
        elif sub_raw[0:4] == "1010":
            BIST_Data_Object.append(metadata(sub_raw[0:4], (31, 28), "BIST Mode", "BIST Shared Test Mode Exit"))
        else:
            BIST_Data_Object.append(metadata(sub_raw[0:4], (31, 28), "BIST Mode", "Reserved"))
        BIST_Data_Object.append(metadata(sub_raw[4:32], (27, 0), "Reserved"))
        self._value = [(metadata(sub_raw, (0, 31), "BIST Data Object", BIST_Data_Object))]
        if num_objs > 1:
            self._value.append(metadata(lst2str(data[4:num_objs*4]), (32, num_objs*32-1), "Test Data",
                                        f'0x{bytes(data[4:num_objs*4]).hex().upper()}'))


class Sink_Capabilities(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        num_objs = kwargs["header"][1].value()
        self._value = []
        for i in range(num_objs):
            sub_raw = lst2str(data[i*4:(i+1)*4])
            self._value.append(sink_pdo_type(sub_raw)(sub_raw, (i*32, (i+1)*32-1), f"PDO {i+1}"))


class Battery_Status(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        BSDO_raw = lst2str(data[0:4])
        BSDO = [
            metadata(BSDO_raw[0:16], (31, 16), "Battery Present Capacity", f"{int(BSDO_raw[0:16], 2) / 10}Wh"),
        ]
        Batter_Info = [
            metadata(BSDO_raw[23], 0, "Invalid Battery Reference", bool(int(BSDO_raw[23]))),
            metadata(BSDO_raw[22], 1, "Battery Present", bool(int(BSDO_raw[22]))),
        ]
        if BSDO_raw[22] == '1':
            if BSDO_raw[20:22] == "00":
                Batter_Info.append(metadata(BSDO_raw[20:22], (3, 2), 
                                           "Battery Charging Status", "Battery is Charging"), 2)
            elif BSDO_raw[20:22] == "01":
                Batter_Info.append(metadata(BSDO_raw[20:22], (3, 2), 
                                           "Battery Charging Status", "Battery is Discharging"), 2)
            elif BSDO_raw[20:22] == "10":
                Batter_Info.append(metadata(BSDO_raw[20:22], (3, 2), 
                                           "Battery Charging Status", "Battery is Idle"), 2)
            elif BSDO_raw[20:22] == "11":
                Batter_Info.append(metadata(BSDO_raw[20:22], (3, 2), 
                                           "Battery Charging Status", "Reserved"), 2)
        elif BSDO_raw[22] == '0':
            Batter_Info.append(metadata(BSDO_raw[20:22], (3, 2), 
                                       "Battery Charging Status", "Reserved"), 2)
        Batter_Info.append(metadata(BSDO_raw[16:20], (7, 4), "Reserved"))
        BSDO.append(metadata(BSDO_raw[16:24], (15, 8), "Battery Info", Batter_Info))
        BSDO.append(metadata(BSDO_raw[24:32], (7, 0), "Reserved"))
        self._value = [metadata(BSDO_raw, (0, 31), "BSDO", BSDO)]

# TODO
class Alert(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')

# TODO
class Get_Country_Info(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')

# TODO
class Enter_USB(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')


class EPR_Request(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')
        self._value = []
        rdo_raw = lst2str(data[0:4])
        copy_of_pdo_raw = lst2str(data[4:8])
        copy_of_pdo = pdo_type(copy_of_pdo_raw)(copy_of_pdo_raw, (32, 63), "Copy of PDO")
        self._value.append(rdo_type(copy_of_pdo)(rdo_raw, (0, 31), "RDO", pdo=copy_of_pdo))
        self._value.append(copy_of_pdo)

# TODO
class EPR_Mode(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')

# TODO
class Source_Info(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')

# TODO
class Revision(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')

# TODO
class Vendor_Defined(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Objects")
        self._raw = lst2str(data, '>')


def provide_ext(msg: metadata):
    if msg["Extended Message Header"] is None:
        return False
    ext_header = msg["Extended Message Header"]
    if ext_header["Chunked"].value():
        if not ext_header["Request Chunk"].value():
            return True
    return False


def need_ext(ext_header: ex_msg_header):
    if ext_header["Chunked"].value():
        if ext_header["Chunk Number"].value() > 0:
            return True
    return False

# TODO
class Source_Capabilities_Extended(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Status(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Get_Battery_Cap(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Get_Battery_Status(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Battery_Capabilities(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Get_Manufacturer_Info(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Manufacturer_Info(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Security_Request(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Security_Response(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Firmware_Update_Request(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Firmware_Update_Response(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class PPS_Status(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Country_Info(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Country_Codes(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Sink_Capabilities_Extended(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Extended_Control(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')


class EPR_Source_Capabilities(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')
        num_objs = kwargs["header"][1].value()
        ex_header = kwargs["ex_header"]
        if ex_header["Request Chunk"].value():
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

    def _get_full_num_objs(self) -> int:
        return self._full_num_objs

    def full_raw(self) -> str:
        return self._full_raw

    def full_value(self) -> list:
        return self._full_value
    
    def __str__(self):
        return f"{self._full_value}"
    
    def __repr__(self):
        return f"{self._field}: {self._full_value}"

    def __getitem__(self, field) -> metadata:
        if self._full_value == "Incomplete Data":
            return None
        if isinstance(field, str):
            return self._field_map.get(field, None)
        else:
            return self._full_value[field]


# TODO
class EPR_Sink_Capabilities(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')

# TODO
class Vendor_Defined_Extended(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')


class Reserved(metadata):
    def __init__(self, data, bit_loc, **kwargs):
        super().__init__(bit_loc=bit_loc, field="Data Block")
        self._raw = lst2str(data, '>')


class pd_msg(metadata):
    def __init__(self, data: list, last_pdo: metadata=None, last_ext: metadata=None):
        super().__init__(field="pd")
        end_of_msg = data[1] + 2
        self._raw = lst2str(data[0:end_of_msg], '>')
        self._bit_loc = (0, (end_of_msg) * 8 - 1)
        self._value = [
            metadata(lst2str([data[1]]), (8, 15), "Length", data[1]),
            metadata(lst2str([data[2]]), (16, 23), "SOP*", SOP[data[2]]),
            msg_header(lst2str(data[3:5]), (24, 39), SOP[data[2]])
        ]

        end_of_msg = 5 + self._value[2][1].value() * 4

        if self._value[2]["Extended"].value():
            self._value.append(ex_msg_header(lst2str(data[5:7]), (40, 55)))
            self._value.append(globals()[self._value[2]["Message Type"].value()](data[7:end_of_msg],
                                                                             (56, (end_of_msg)*8-1),
                                                                             sop=SOP[data[2]],
                                                                             header=self._value[2],
                                                                             ex_header=self._value[3],
                                                                             last_pdo=last_pdo,
                                                                             last_ext=last_ext))
        else:
            if self._value[2]["Message Type"].value() in globals():
                self._value.append(globals()[self._value[2]["Message Type"].value()](data[5:end_of_msg],
                                                                                 (40, (end_of_msg)*8-1),
                                                                                 sop=SOP[data[2]],
                                                                                 header=self._value[2],
                                                                                 last_pdo=last_pdo))


class WITRN_HID:
    def __init__(self, vid=K2_TARGET_VID, pid=K2_TARGET_PID):
        self.data = None
        self.timestamp = None
        self.last_pdo = None
        self.last_ext = None

        self.dev = hid.device()
        self.dev.open(vid, pid)

    def read_data(self) -> list:
        self.timestamp = time.strftime("%H:%M:%S", time.localtime()) + f".{(int(time.time()*1000)%1000):03d}"
        self.data = self.dev.read(64)
        return self.data

    def general_unpack(self, data: list = None) -> metadata:
        if data is None:
            if self.data is None:
                raise ValueError("No data available to unpack")
            elif len(self.data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            return self.timestamp, general_msg(self.data)
        else:
            if len(data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            return general_msg(data)

    def pd_unpack(self, data: list = None) -> metadata:
        if data is None:
            if self.data is None:
                raise ValueError("No data available to unpack")
            elif len(self.data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            msg = pd_msg(self.data, self.last_pdo, self.last_ext)
            if is_pdo(msg):
                self.last_pdo = msg
            if provide_ext(msg):
                self.last_ext = msg
            return self.timestamp, msg
        else:
            if len(data) < 64:
                raise ValueError("Data length is less than expected (64 bytes)")
            return pd_msg(data)
        
    def auto_unpack(self, data: list = None) -> metadata:
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
                return self.pd_unpack(data)
            

    def close(self):
        self.dev.close()


if __name__ == "__main__":
    k2 = WITRN_HID()
    while True:
        k2.read_data()
        _, pkg = k2.auto_unpack()
        if pkg.field() == "pd":
            print(pkg)