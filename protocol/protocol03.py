# protocol03.py
"""
   This module provides how to pack and unpack waggle message version 0.3.
   In Python3, data will be treated using bytearray.
"""
from crcmod.predefined import mkCrcFun
from struct import pack
import io
import time, logging, sys, struct
import os.path

from baseProtocol import WaggleMessage

class WaggleProtocol03(object):
    #Where each piece of information in a packet header is stored, by byte
    # Total header size is 40 bytes.
    HEADER_LOCATIONS = {
        "prot_ver"         : 0,
        "flags"            : 1,
        "len_body"         : 2,
        "time"             : 4,
        "msg_mj_type"      : 8,
        "msg_mi_type"      : 9,
        "snd_session"      : 10,    # For Friday: just zero. Eventually automatic
        "s_uniqid"         : 12,    # Find from /etc/waggle/hostname
        "ext_header"       : 20,    # Just 0
        "resp_session"     : 22,    # Normally 0, sometimes used
        "r_uniqid"         : 24,    # Defined as 0 for the cloud
        "snd_seq"          : 32,    # Tracked by this module
        "resp_seq"         : 35,    # Normally 0, sometimes used
        "crc-16"           : 38
    }
    #The length of each piece of data, in bytes
    HEADER_BYTELENGTHS = {
        "prot_ver"         : 1,
        "flags"            : 1,
        "len_body"         : 2,
        "time"             : 4,
        "msg_mj_type"      : 1,
        "msg_mi_type"      : 1,
        "snd_session"      : 2,
        "s_uniqid"         : 8,
        "ext_header"       : 2,
        "resp_session"     : 2,
        "r_uniqid"         : 8,
        "snd_seq"          : 3,
        "resp_seq"         : 3,
        "crc-16"           : 2
    }

    #The total header length
    HEADER_LENGTH = 40
    FOOTER_LENGTH = 4
    MAX_SEQ_NUMBER = pow(2,8*HEADER_BYTELENGTHS["snd_seq"])
    MAX_PACKET_SIZE = 1024

    VERSION = "0.3"

    #Create the CRC functions
    crc32fun = mkCrcFun('crc-32')
    crc16fun = mkCrcFun('crc-16')

    crc16_position = HEADER_LOCATIONS['crc-16']

    def __init__(self, s_uniqid_hex, s_uniqid_hex_int):
        self.S_UNIQUEID_HEX = s_uniqid_hex
        self.S_UNIQUEID_HEX_INT = s_uniqid_hex_int

    def ver(self):
        return VERSION

    def pack(self, header_data, message_data="", sequence):
        """
            Takes header and message information and yields packets representing that data.

            :param dictionary header_data: A dictionary containing the header data
            :param string/FileObject message_data: The data to be packed into a Packet
            :yields: string
            :raises KeyError: A KeyError will be raised if the header_data dictionary is not properly formatted
        """

        #Generate the automatic fields
        auto_header = {
            "prot_ver"         : self.VERSION,
            "flags"            : (1,1,True),
            "len_body"         : len(message_data),
            "time"             : int(time.time()),
            "snd_session"      : 0,
            "s_uniqid"         : self.S_UNIQUEID_HEX_INT,
            "ext_header"       : 0,
            "resp_session"     : 0,
            "r_uniqid"         : 0,
            "snd_seq"          : sequence,
            "resp_seq"         : 0,
        }
        #and update them with user-supplied values
        auto_header.update(header_data)


        #If it's a string, make it a file object
        if(type(message_data) is str):
            message_data = StringIO.StringIO(message_data)

        #If it's under 1K, send it off as a single packet
        #Jump to the end of the file
        message_data.seek(0,2)

        header = None
        
        #See if it is less than 1K
        if(message_data.tell() < MAX_PACKET_SIZE):
            try:
                header = pack_header(auto_header)
            except KeyError as e:
                raise

            #Save the short message to a string
            message_data.seek(0)
            msg = message_data.read()
            message_data.close()

            #Calculate the CRC, pack it all up, and return the result.
            SEQUENCE = (SEQUENCE + 1) % MAX_SEQ_NUMBER
            msg_crc32 = bin_pack(crc32fun(msg),FOOTER_LENGTH)

            yield header + msg + msg_crc32

        #Multi-packet
        else:
            length = message_data.tell()
            message_data.seek(0)
            packetNum = 0

            # Create smaller packets MAX_PACKET_SIZE bytes at a time, also attach packet number
            while length > MAX_PACKET_SIZE:
                try:
                    header = pack_header(auto_header)
                except KeyError as e:
                    raise
                msg = bin_pack(packetNum,4) + message_data.read(MAX_PACKET_SIZE)
                SEQUENCE = (SEQUENCE + 1) % MAX_SEQ_NUMBER
                packetNum += 1
                msg_crc32 = bin_pack(crc32fun(msg),FOOTER_LENGTH)
                yield header + msg + msg_crc32
                length -= MAX_PACKET_SIZE

            # Finish sending the message
            if length > 0:
                header = pack_header(auto_header)
                msg = bin_pack(packetNum,4) + message_data.read(MAX_PACKET_SIZE)
                SEQUENCE = (SEQUENCE + 1) % MAX_SEQ_NUMBER
                msg_crc32 = bin_pack(crc32fun(msg),FOOTER_LENGTH)
                yield header + msg + msg_crc32

    def unpack(self, packet):
        """
            Turns a packet object into a tuple containing the header data and message body

            :param string packet: The packet data to be unpacked
            :rtype: tuple(dictionary, string)
            :raises IOError: An IOError will be raised if a CRC fails in the packet
            :raises KeyError: An IndexError will be raised if a packet header is the wrong length
        """
        #crc32fun = mkCrcFun('crc-32')
        header = None
        if(crc32fun(packet[HEADER_LENGTH:-FOOTER_LENGTH]) != _bin_unpack(packet[-FOOTER_LENGTH:])):
            raise IOError("Packet body CRC-32 failed.")
        try:
            header = _unpack_header(packet[:HEADER_LENGTH])
        except Exception as e:
            logger.error("_unpack_header failed: "+str(e))
            raise

        return (header, packet[HEADER_LENGTH:-FOOTER_LENGTH])

    def pack_header(self, header_data):
        """
            Attempt to pack the data from the header_data dictionary into binary format according to Waggle protocol.

            :param dictionary header_data: The header data to be serialized
            :rtype: string
            :raises KeyError: An exception will be raised if the provided dictionary does not contain required information
        """

        header = str()
        try:
            header += _pack_version(header_data["prot_ver"])                                                   # Serialize protocol version
            header += _pack_flags(header_data["flags"])                                                        # Packet flags
            header += bin_pack(header_data["len_body"],HEADER_BYTELENGTHS["len_body"])          # Length of message body
            header += bin_pack(header_data["time"],HEADER_BYTELENGTHS["time"])                  # Timestamp
            header += bin_pack(header_data["msg_mj_type"], HEADER_BYTELENGTHS["msg_mj_type"])   # Message Major Type
            header += bin_pack(header_data["msg_mi_type"], HEADER_BYTELENGTHS["msg_mi_type"])   # Message Minor Type
            header += bin_pack(header_data["ext_header"], HEADER_BYTELENGTHS["ext_header"])     # Optional extended header
            header += bin_pack(header_data["s_uniqid"],HEADER_BYTELENGTHS["s_uniqid"])          # Sender unique ID
            header += bin_pack(header_data["r_uniqid"],HEADER_BYTELENGTHS["r_uniqid"])          # Recipient unique ID
            header += bin_pack(header_data["snd_session"],HEADER_BYTELENGTHS["snd_session"])    # Send session number
            header += bin_pack(header_data["resp_session"],HEADER_BYTELENGTHS["resp_session"])  # Response session number
            header += bin_pack(header_data["snd_seq"],HEADER_BYTELENGTHS["snd_seq"])            # Send sequence number
            header += bin_pack(header_data["resp_seq"],HEADER_BYTELENGTHS["resp_seq"])          # Response sequence number
        except KeyError as e:
            raise KeyError("Header packing failed. The required dictionary entry %s was missing!" % str(e))


        #Compute the header CRC and stick it on the end
        #crc16 = mkCrcFun('crc-16')
        header += bin_pack(crc16fun(header),HEADER_BYTELENGTHS['crc-16'])

        return header


    def get_header(self, packet):
        """
            Given a complete packet, this method will return the header as a dictionary.

            :param string packet: A complete packet.
            :rtype: dictionary
            :raises IndexError: An IndexError will be raised if the packed header is not 40 bytes long
            :raises IOError: An IOError will be raised if the packet header fails its CRC-16 check
        """
        try:
            header = _unpack_header(packet[:HEADER_LENGTH])
            return header
        except Exception as e:
            raise

    def _unpack_header(self, packed_header):
        """
            Given a packed header, this method will return a dictionary with the unpacked contents.

            :param string packed_header: A string representing a waggle header
            :rtype: Dictionary
            :raises IndexError: An IndexError will be raised if the packed header is not 40 bytes long
            :raises IOError: An IOError will be raised if the packet header fails its CRC-16 check
        """

        # Check header length
        if len(packed_header) != HEADER_LENGTH:
            raise IndexError("Tried to unpack a waggle header that was %d instead of %d bytes long." % (len(packed_header), HEADER_LENGTH ) )

        header_IO = StringIO.StringIO(packed_header)

        #Check the CRC
        #CRC16 = mkCrcFun('CRC-16')
        header_IO.seek(HEADER_LOCATIONS["crc-16"])
        headerCRC = header_IO.read(2)
        if(crc16fun(packed_header[:-2]) != _bin_unpack(headerCRC)):
            raise IOError("Header CRC-16 check failed")
        header_IO.seek(0)

        # The header passed the CRC check. Hooray! Now return a dictionary containing the info.
        header = {
            "prot_ver"     : _unpack_version(header_IO.read(HEADER_BYTELENGTHS["prot_ver"])),        # Load protocol version
            "flags"        : _unpack_flags(header_IO.read(HEADER_BYTELENGTHS["flags"])),             # Load flags
            "len_body"     : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["len_body"])),            # Load message body length
            "time"         : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["time"])),                # Load time
            "msg_mj_type"  : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["msg_mj_type"])),         # Load message major type
            "msg_mi_type"  : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["msg_mi_type"])),         # Load message minor type
            "ext_header"   : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["ext_header"])),          # Load extended header
            "s_uniqid"     : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["s_uniqid"])),            # Load sender unique ID
            "r_uniqid"     : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["r_uniqid"])),            # Load recipient unique ID
            "snd_session"  : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["snd_session"])),         # Load send session number
            "resp_session" : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["resp_session"])),        # Load recipient session number
            "snd_seq"      : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["snd_seq"])),             # Load send sequence number
            "resp_seq"     : _bin_unpack(header_IO.read(HEADER_BYTELENGTHS["resp_seq"]))             # Load recieve sequence number
        }

        header_IO.close()
        return header