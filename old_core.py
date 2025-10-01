import hid
import struct
import time

__all__ = ["WITRN_HID"]


K2_TARGET_VID = 0x0716
K2_TARGET_PID = 0x5060


class WITRN_HID:
    __API__ = ["Nowtime", "Ah", "Wh", "Rectime", "Runtime", 
               "DP", "DM", "Temperature", "VBus", "Current", "Group"]
    
    _fmt = struct.Struct(
        "<xxxxxxxxxxxxxxffIIffxxxxfffBxxxxxxxxx"
        )

    def __init__(self, vid=K2_TARGET_VID, pid=K2_TARGET_PID):
        self.Nowtime = None
        self.Ah = None
        self.Wh = None
        self.Rectime = None
        self.Runtime = None
        self.DP = None
        self.DM = None
        self.Temperature = None
        self.VBus = None
        self.Current = None
        self.Group = None
        self.data = None

        self.dev = hid.device()
        self.dev.open(vid, pid)

    def read_data(self, dev: hid.device=None) -> list:
        if dev is not None:
            data = dev.read(64)
            t = time.localtime()
            ms = int(time.time() * 1000) % 1000
            self.Nowtime = time.strftime("%H:%M:%S", t) + f".{ms:03d}"
            return data
        else:
            self.data = self.dev.read(64)
            t = time.localtime()
            ms = int(time.time() * 1000) % 1000
            self.Nowtime = time.strftime("%H:%M:%S", t) + f".{ms:03d}"
            return self.data

    def unpack(self, data: list=None) -> tuple:
        if data is None:
            if self.data is None:
                raise ValueError("No data available to unpack")
            data = self.data
        if len(data) < 64:
            raise ValueError("Data length is less than expected (64 bytes)")
        package = self._fmt.unpack(bytes(data))
        (
            self.Ah,
            self.Wh,
            self.Rectime,
            self.Runtime,
            self.DP,
            self.DM,
            self.Temperature,
            self.VBus,
            self.Current,
            self.Group
        ) = package
        return (self.Nowtime,) + package

    def now(self) -> tuple:
        self.read_data()
        return self.unpack()

    def close(self):
        self.dev.close()


if __name__ == "__main__":
    # Demo
    # Create an instance of WITRN_HID with the VID and PID
    k2 = WITRN_HID(K2_TARGET_VID, K2_TARGET_PID)

    # Fast call
    # Return a tuple of time and unpacked data
    # Member variables within the class will also be updated synchronously
    print(k2.now())
    print(k2.Nowtime, k2.Ah, k2.Wh, k2.Rectime, k2.Runtime,
          k2.DP, k2.DM, k2.Temperature, k2.VBus, k2.Current, k2.Group)

    # Only read the data stream
    # Can accept a parameter of type 'hid.device'
    # If no device is specified, it will read from the instance device
    # Return a list of bytes
    # Update the member variable 'data' when no parameter is provided
    k2.read_data()
    print(k2.data)
    print(k2.read_data(k2.dev)) # The second 'k2.dev' means a different device

    # Only unpack the data
    # Can accept a parameter of type 'list'
    # If no data is specified, it will unpack the last read data from the instance
    # Update the member variables with the unpacked data
    k2.unpack()
    print(k2.Nowtime, k2.Ah, k2.Wh, k2.Rectime, k2.Runtime,
          k2.DP, k2.DM, k2.Temperature, k2.VBus, k2.Current, k2.Group)
    print(k2.unpack(k2.data))  # The second 'k2.data' means a different data source

    # Close the device
    k2.close()