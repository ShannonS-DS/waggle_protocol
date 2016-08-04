#!/usr/bin/env python3

# baseProtocol.py
"""
	This module provides base class of Waggle message protocol. Each version of Waggle message protocol extends the base class.
"""
from crcmod.predefined import mkCrcFun

from protocol03 import *
from protocol04 import *

class WaggleMessage(object):
	#The /etc/waggle folder has waggle specific information
	S_UNIQUEID_HEX=None
	S_UNIQUEID_HEX_INT = 0
	#Sequence becomes zero when the node starts again or when the package is
	#reimported
    SEQUENCE = 0

    PROTOCOLS = {}

    def __init__(self):
    	"""
    		Add supported protocols.
    	"""
    	p03 = WaggleProtocol03()
    	PROTOCOLS[p03.ver()] = p03

    	p04 = WaggleProtocol04()
    	PROTOCOLS[p04.ver()] = p04

	def pack(self, header_data, message_data):
		"""
			Makes a waggle message. This should be overridden in child class.
			:param dictionary header_data: A dictionary containing the header data
			:param string/FileObject message_data: The data to be packed into a Packet
			:yields: string
			:raises Exception: The protocol does not exist.
		"""
		prot = None
		if 'prot_ver' in header_data:
			protocol_version = header_data['prot_ver']
			if protocol_version in PROTOCOLS:
				prot = PROTOCOLS[protocol_version]

		if not prot:
			return prot.pack(header_data, message_data, self.SEQUENCE)
		else
			raise Exception("protocol does not exist")

	def set_header_field(self, header_bytearray, field, value):
		"""
			(bytearray header) Sets header field in an bytearray. Value also has to be an bytearray.
		"""
		try:
			field_position = HEADER_LOCATIONS[field]
			field_length = HEADER_BYTELENGTHS[field]
		except Exception as e:
			logger.error("Field name unknown: %s" % (str(e)) )
			raise

		if len(value) != field_length:
			e = ValueError("data length: %d bytes, but field is of size: %d bytes (field: %s)" % (len(value), field_length, field) )
			logger.error(str(e))
			raise e

		if (len(header_bytearray) != HEADER_LENGTH):
			e = ValueError("header length is not correct: %d vs HEADER_LENGTH=%d" %(len(header_bytearray), HEADER_LENGTH) )
			logger.error(str(e))
			raise e

		for i in range(field_length):
			header_bytearray[field_position+i] = value[i]

	def write_header_crc(header_bytearray):
		"""
			(bytearray header) Calculates the header crc and accordingly sets the crc-16 field.
		"""
		new_crc = crc16fun(str(header_bytearray[:crc16_position]))
		new_crc_packed = bin_pack(new_crc,HEADER_BYTELENGTHS['crc-16'])
		set_header_field(header_bytearray, 'crc-16', new_crc_packed)

	def bin_pack(n, size):
		"""
		Takes in an int n and returns it in binary string format of a specified length

		:param int n: The integer to be converted to binary
		:param int size: The number of bytes that the integer will be represented with
		:rtype: string
		"""
		packed = bytearray(size)

		for i in range(1, size + 1):
			packed[-i] = 0xff & (n >> (i - 1)*8)

		return str(packed)

	def _pack_flags(flags):
		"""
		For internal use.
		Takes a tuple representing the message priorities and FIFO/LIFO preference and packs them to one byte.

		:param tuple(int,int,bool) flags:
		:rtype: string
		"""
		return chr((flags[0] << 5) | (flags[1] << 2) | (flags[2] << 1))


	def _unpack_flags(flagByte):
		"""
		For internal use.
		Takes in the priority byte from the header and returns a tuple containing the correct information.

		:param string flagByte: The priority byte from the header
		:rtype: Tuple(Int, Int, Bool)
		"""
		return ((ord(flagByte) & 0xe0) >> 5, (ord(flagByte) & 0x1c) >> 2, bool((ord(flagByte) & 0x02) >> 1))


	def _unpack_version(version):
		"""
		For internal use.
		Returns the protocol in string form.

		:param string version: byte representing the version
		:rtype: string
		"""
		v = ord(version)
		major = v & 0xf0
		minor = v & 0x0f

		# return the version in human-readable form. For example: "0x03" becomes "0.3".
		return str(major) + "." + str(minor)

	def _pack_version(version):
		"""
		For internal use.
		Returns the protocol as a binary

		:param string version: The version in human-readable format, i.e. "0.3"
		:rtype: The protocol version as a 1 byte string
		"""
		versions = version.split(".")
		major = int(versions[0])
		minor = int(versions[1])

		return chr((major << 4) | (0xf & minor))

	def _bin_unpack(string):
		"""
		For internal use.
		Takes in a string and returns it in integer format

		:param string string: The binary string to read
		:rtype: int
		"""
		x = 0

		for i in range(1, len(string) + 1):
			x = x | (ord(string[-i]) << (i - 1)*8)

		return x