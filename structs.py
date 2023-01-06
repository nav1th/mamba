from ctypes import Structure,c_ubyte,c_uint16
ETHER_ADDR_LEN = 6
class sniff_ethernet(Structure):
    _fields_ = [
                ("ether_dhost", c_ubyte * ETHER_ADDR_LEN),
                ("ether_shost", c_ubyte * ETHER_ADDR_LEN),
                ("ether_type",c_uint16)
               ]
