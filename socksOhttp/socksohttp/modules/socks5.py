
#https://www.ietf.org/rfc/rfc1928.txt
#https://tools.ietf.org/html/rfc1929
#https://tools.ietf.org/html/rfc1961

import io
import enum
import ipaddress
import socket
import asyncio
import uuid

from ..comms import *

module_name = 'socks5'

async def readexactly_or_exc(reader, n, timeout = None):
	"""
	Helper function to read exactly N amount of data from the wire.
	:param reader: The reader object
	:type reader: asyncio.StreamReader
	:param n: The maximum amount of bytes to read.
	:type n: int
	:param timeout: Time in seconds to wait for the reader to return data
	:type timeout: int
	:return: bytearray
	"""
	try:
		data = await asyncio.wait_for(reader.readexactly(n), timeout = timeout)
	except:
		raise ConnectionClosed()

	if data == b'':
		if reader.at_eof():
			raise ConnectionClosed()

	return data


async def read_or_exc(reader, n, timeout = None):
	"""
	Helper function to read N amount of data from the wire.
	:param reader: The reader object
	:type reader: asyncio.StreamReader
	:param n: The maximum amount of bytes to read. BEWARE: this only sets an upper limit of the data to be read
	:type n: int
	:param timeout: Time in seconds to wait for the reader to return data
	:type timeout: int
	:return: bytearray
	"""
	try:
		data = await asyncio.wait_for(reader.read(n), timeout = timeout)
	except:
		raise ConnectionClosed()

	if data == b'':
		if reader.at_eof():
			raise ConnectionClosed()

	return data

class SOCKS5ServerMode(enum.Enum):
	OFF    = enum.auto()
	NORMAL = enum.auto()
	EVIL   = enum.auto()


class SOCKS5ServerState(enum.Enum):
	NEGOTIATION = 0
	NOT_AUTHENTICATED = 1
	REQUEST = 3 
	RELAYING = 4


class SOCKS5Method(enum.Enum):
	NOAUTH = 0x00
	GSSAPI = 0x01
	PLAIN  = 0x02
	# IANA ASSIGNED X'03' to X'7F'
	# RESERVED FOR PRIVATE METHODS X'80' to X'FE'

	NOTACCEPTABLE = 0xFF


class SOCKS5Command(enum.Enum):
	CONNECT = 0x01
	BIND = 0x02
	UDP_ASSOCIATE = 0x03


class SOCKS5AddressType(enum.Enum):
	IP_V4 = 0x01
	DOMAINNAME = 0x03
	IP_V6 = 0x04


class SOCKS5ReplyType(enum.Enum):
	SUCCEEDED = 0X00 # o  X'00' succeeded
	FAILURE = 0x01 # o  X'01' general SOCKS server failure
	CONN_NOT_ALLOWED = 0x02#         o  X'02' connection not allowed by ruleset
	NETWORK_UNREACHABLE = 0x03 #o  X'03' Network unreachable
	HOST_UNREACHABLE = 0x04#o  X'04' Host unreachable
	CONN_REFUSED = 0x05 #o  X'05' Connection refused
	TTL_EXPIRED = 0x06 #o  X'06' TTL expired
	COMMAND_NOT_SUPPORTED = 0x07 #o  X'07' Command not supported
	ADDRESS_TYPE_NOT_SUPPORTED = 0x08 #o  X'08' Address type not supported
	#o  X'09' to X'FF' unassigned


class SOCKS5SocketParser:
	def __init__(self, protocol = socket.SOCK_STREAM):
		self.protocol = protocol

	def parse(self, soc, packet_type):
		return packet_type.from_bytes(self.read_soc(soc, packet_type.size))

	def read_soc(self, soc, size):
		data = b''
		while True:
			temp = soc.recv(4096)
			if temp == '':
				break
			data += temp
			if len(data) == size:
				break
		return data


class SOCKS5CommandParser:
	# the reason we need this class is: SOCKS5 protocol messages doesn't have a type field,
	# the messages are parsed in context of the session itself.
	def __init__(self, protocol = socket.SOCK_STREAM):
		self.protocol = protocol #not used atm

	def parse(self, buff, session):
		if session.current_state == SOCKS5ServerState.NEGOTIATION:
			return SOCKS5Nego.from_buffer(buff)
		
		if session.current_state == SOCKS5ServerState.NOT_AUTHENTICATED:
			if session.mutual_auth_type == SOCKS5Method.PLAIN:
				return SOCKS5PlainAuth.from_buffer(buff)
			else:
				raise Exception('Not implemented!')

		if session.current_state == SOCKS5ServerState.REQUEST:
			return SOCKS5Request.from_buffer(buff)

	async def from_streamreader(reader, session, timeout = None):
		if session.current_state == SOCKS5ServerState.NEGOTIATION:
			t = await asyncio.wait_for(SOCKS5Nego.from_streamreader(reader), timeout = timeout)
			return t
		
		if session.current_state == SOCKS5ServerState.NOT_AUTHENTICATED:
			if session.mutual_auth_type == SOCKS5Method.PLAIN:
				t = await asyncio.wait_for(SOCKS5PlainAuth.from_streamreader(reader), timeout = timeout)
				return t
			else:
				raise Exception('Not implemented!')

		if session.current_state == SOCKS5ServerState.REQUEST:
			t = await asyncio.wait_for(SOCKS5Request.from_streamreader(reader), timeout = timeout)
			return t


class SOCKS5AuthHandler:
	def __init__(self, authtype, creds = None):
		self.authtype  = authtype
		self.creds = creds

	def do_AUTH(self, msg):
		if self.authtype == SOCKS5Method.PLAIN:
			if not isinstance(msg, SOCKS5PlainAuth):
				raise Exception('Wrong message/auth type!')

			if self.creds is None:
				return True, SOCKS5PlainCredentials(msg.UNAME, msg.PASSWD)
			else:
				if msg.UNAME in self.creds:
					if msg.PASSWD == self.creds[msg.UNAME]:
						return True, SOCKS5PlainCredentials(msg.UNAME, msg.PASSWD)

				return False, SOCKS5PlainCredentials(msg.UNAME, msg.PASSWD)

		elif self.authtype == SOCKS5Method.GSSAPI:
			raise Exception('Not implemented! yet')
		
		else:
			raise Exception('Not implemented!')


class SOCKS5PlainCredentials:
	def __init__(self, username, password):
		self.username = username
		self.password = password


	def toCredential(self):
		res = {
			'type'     : 'PLAIN', 
			'user'     : self.username,
			'cleartext': self.password,
			'fullhash' : '%s:%s' % (self.username, self.password)
		}
		return res


class SOCKS5PlainAuth:
	def __init__(self):
		self.VER = None
		self.ULEN = None
		self.UNAME = None
		self.PLEN = None
		self.PASSWD = None

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		auth = SOCKS5PlainAuth()
		t = await read_or_exc(reader, 1, timeout = timeout)
		auth.VER = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader, 1, timeout = timeout)
		auth.ULEN = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader, auth.ULEN, timeout = timeout)
		auth.UNAME = t.decode()
		t = await read_or_exc(reader, 1, timeout = timeout)
		auth.PLEN = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader, auth.PLEN, timeout = timeout)
		auth.PASSWD = t.decode()

		return auth

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5PlainAuth.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		auth = SOCKS5PlainAuth()
		auth.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
		auth.ULEN = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		auth.UNAME = buff.read(auth.ULEN).decode()
		auth.PLEN = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		auth.PASSWD = buff.read(auth.PLEN).decode()

		return auth

	@staticmethod
	def construct(username, password):
		auth = SOCKS5PlainAuth()
		auth.VER    = 5
		auth.ULEN   = len(username)
		auth.UNAME  = username
		auth.PLEN   = len(password)
		auth.PASSWD = password

		return auth

	def to_bytes(self):
		t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
		t += self.ULEN.to_bytes(1, byteorder = 'big', signed = False)
		t += self.UNAME.encode()
		t += self.PLEN.to_bytes(1, byteorder = 'big', signed = False)
		t += self.PASSWD.encode()
		return t


class SOCKS5Nego:
	def __init__(self):
		self.VER = None
		self.NMETHODS = None
		self.METHODS = None

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		nego = SOCKS5Nego()
		t = await read_or_exc(reader,1, timeout = timeout)
		nego.VER = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		nego.NMETHODS = int.from_bytes(t, byteorder = 'big', signed = False)
		nego.METHODS = []
		for i in range(nego.NMETHODS):
			t = await read_or_exc(reader,1, timeout = timeout)
			nego.METHODS.append(SOCKS5Method(int.from_bytes(t, byteorder = 'big', signed = False)))

		return nego

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5Nego.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		nego = SOCKS5Nego()
		nego.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
		nego.NMETHODS = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
		nego.METHODS = []
		for i in range(nego.NMETHODS):
			nego.METHODS.append(SOCKS5Method(int.from_bytes(buff.read(1), byteorder = 'big', signed = False)))
		return nego

	@staticmethod
	def construct(methods):
		if not isinstance(methods, list):
			methods = [methods]
		nego = SOCKS5Nego()
		nego.VER = 5
		nego.NMETHODS = len(methods)
		nego.METHODS = methods
		return nego

	def to_bytes(self):
		t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
		t += self.NMETHODS.to_bytes(1, byteorder = 'big', signed = False)
		for method in self.METHODS:
			t += method.value.to_bytes(1, byteorder = 'big', signed = False)
		return t

class SOCKS5NegoReply:
	def __init__(self):
		self.VER = None
		self.METHOD = None

	def __repr__(self):
		t  = '== SOCKS5NegoReply ==\r\n'
		t += 'VER: %s\r\n' % self.VER
		t += 'METHOD: %s\r\n' % self.METHOD
		return t

	@staticmethod
	def from_socket(soc):
		data = b''
		total_size = 2
		while True:
			temp = soc.recv(1024)
			if temp == b'':
				break
			data += temp
			if len(data) >= total_size:
				break
		print(data)
		return SOCKS5NegoReply.from_bytes(data)

	async def from_streamreader(reader, timeout = None):
		rep = SOCKS5NegoReply()
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.VER = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.METHOD = SOCKS5Method(int.from_bytes(t, byteorder = 'big', signed = False))
		
		return rep

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5NegoReply.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		rep = SOCKS5NegoReply()
		rep.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		rep.METHOD = SOCKS5Method(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		return rep

	@staticmethod
	def construct(method):
		rep = SOCKS5NegoReply()
		rep.VER = 5
		rep.METHOD = method
		return rep

	@staticmethod
	def construct_auth(method, ver = 1):
		rep = SOCKS5NegoReply()
		rep.VER = ver
		rep.METHOD = method
		return rep


	def to_bytes(self):
		t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
		t += self.METHOD.value.to_bytes(1, byteorder = 'big', signed = False)
		return t


class SOCKS5Request:
	def __init__(self):
		self.VER = None
		self.CMD = None
		self.RSV = None
		self.ATYP = None
		self.DST_ADDR = None
		self.DST_PORT = None

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		req = SOCKS5Request()
		t = await read_or_exc(reader,1, timeout = timeout)
		req.VER = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		req.CMD = SOCKS5Command(int.from_bytes(t, byteorder = 'big', signed = False))
		t = await read_or_exc(reader,1, timeout = timeout)
		req.RSV = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		req.ATYP = SOCKS5AddressType(int.from_bytes(t, byteorder = 'big', signed = False))
		if req.ATYP == SOCKS5AddressType.IP_V4:
			t = await read_or_exc(reader,4, timeout = timeout)
			req.DST_ADDR = ipaddress.IPv4Address(t)
		elif req.ATYP == SOCKS5AddressType.IP_V6:
			t = await read_or_exc(reader,16, timeout = timeout)
			req.DST_ADDR = ipaddress.IPv6Address(t)

		elif req.ATYP == SOCKS5AddressType.DOMAINNAME:
			t = await read_or_exc(reader,1, timeout = timeout)
			length = int.from_bytes(t, byteorder = 'big', signed = False)
			t = await read_or_exc(reader,length, timeout = timeout)
			req.DST_ADDR = t.decode()

		t = await read_or_exc(reader,2, timeout = timeout)
		req.DST_PORT = int.from_bytes(t, byteorder = 'big', signed = False)

		return req

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5Request.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		req = SOCKS5Request()
		req.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		req.CMD = SOCKS5Command(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		req.RSV = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
		req.ATYP = SOCKS5AddressType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False)) 
		if req.ATYP == SOCKS5AddressType.IP_V4:
			req.DST_ADDR = ipaddress.IPv4Address(buff.read(4))
		elif req.ATYP == SOCKS5AddressType.IP_V6:
			req.DST_ADDR = ipaddress.IPv6Address(buff.read(16))
		elif req.ATYP == SOCKS5AddressType.DOMAINNAME:
			length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
			req.DST_ADDR = buff.read(length).decode()

		req.DST_PORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		return req

	@staticmethod
	def construct(cmd, address, port):
		req = SOCKS5Request()
		req.VER = 5
		req.CMD = cmd
		req.RSV = 0
		if isinstance(address, ipaddress.IPv4Address):
			req.ATYP = SOCKS5AddressType.IP_V4
			req.DST_ADDR = address
		elif isinstance(address, ipaddress.IPv6Address):
			req.ATYP = SOCKS5AddressType.IP_V6
			req.DST_ADDR = address
		elif isinstance(address, str):
			req.ATYP = SOCKS5AddressType.DOMAINNAME
			req.DST_ADDR = address

		req.DST_PORT = port
		return req

	def to_bytes(self):
		t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
		t += self.CMD.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.RSV.to_bytes(1, byteorder = 'big', signed = False)
		t += self.ATYP.value.to_bytes(1, byteorder = 'big', signed = False)
		if self.ATYP == SOCKS5AddressType.DOMAINNAME:
			t += len(self.DST_ADDR).to_bytes(1, byteorder = 'big', signed = False)
			t += self.DST_ADDR.encode()
		else:	
			t += self.DST_ADDR.packed
		t += self.DST_PORT.to_bytes(2, byteorder = 'big', signed = False)
		return t


class SOCKS5Reply:
	def __init__(self):
		self.VER = None
		self.REP = None
		self.RSV = None
		self.ATYP = None
		self.BIND_ADDR= None
		self.BIND_PORT= None

	@staticmethod
	def from_socket(soc):
		data = b''
		total_size = 1024
		while True:
			temp = soc.recv(1024)
			if temp == b'':
				break
			data += temp

			if len(data) > 4:
				rt = SOCKS5AddressType(data[3])
				print(rt)
				if rt == SOCKS5AddressType.IP_V4:
					total_size = 4 + 2 + 4
				if rt == SOCKS5AddressType.IP_V6:
					total_size = 4 + 2 + 16
				if rt == SOCKS5AddressType.DOMAINNAME:
					total_size = 4 + 2 + data[4]
				print(total_size)
			if len(data) >= total_size:
				break

		return SOCKS5Reply.from_bytes(data)

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		rep = SOCKS5Reply()
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.VER = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.REP = SOCKS5ReplyType(int.from_bytes(t, byteorder = 'big', signed = False))
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.RSV = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.ATYP = SOCKS5AddressType(int.from_bytes(t, byteorder = 'big', signed = False))
		if rep.ATYP == SOCKS5AddressType.IP_V4:
			t = await read_or_exc(reader,4, timeout = timeout)
			rep.BIND_ADDR = ipaddress.IPv4Address(t)
		elif rep.ATYP == SOCKS5AddressType.IP_V6:
			t = await read_or_exc(reader,16, timeout = timeout)
			rep.BIND_ADDR = ipaddress.IPv6Address(t)
		elif rep.ATYP == SOCKS5AddressType.DOMAINNAME:
			t = await read_or_exc(reader,1, timeout = timeout)
			length = int.from_bytes(t, byteorder = 'big', signed = False)
			t = await read_or_exc(reader,length, timeout = timeout)
			rep.BIND_ADDR = t.decode()

		t = await read_or_exc(reader,2, timeout = timeout)
		rep.BIND_PORT = int.from_bytes(t, byteorder = 'big', signed = False)
		return rep

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5Reply.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		rep = SOCKS5Reply()
		rep.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
		rep.REP = SOCKS5ReplyType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		rep.RSV = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		rep.ATYP = SOCKS5AddressType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))

		if rep.ATYP == SOCKS5AddressType.IP_V4:
			rep.BIND_ADDR = ipaddress.IPv4Address(buff.read(4))
		elif rep.ATYP == SOCKS5AddressType.IP_V6:
			rep.BIND_ADDR = ipaddress.IPv6Address(buff.read(16))
		elif rep.ATYP == SOCKS5AddressType.DOMAINNAME:
			length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
			rep.BIND_ADDR = buff.read(length).decode()

		rep.BIND_PORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)

		return rep

	@staticmethod
	def construct(reply, address, port): 
		rep = SOCKS5Reply()
		rep.VER = 5
		rep.REP = reply
		rep.RSV = 0
		if isinstance(address, ipaddress.IPv4Address):
			rep.ATYP = SOCKS5AddressType.IP_V4
			rep.DST_ADDR = address
		elif isinstance(address, ipaddress.IPv6Address):
			rep.ATYP = SOCKS5AddressType.IP_V6
			rep.DST_ADDR = address
		elif isinstance(address, str):
			rep.ATYP = SOCKS5AddressType.DOMAINNAME
			rep.DST_ADDR = address

		rep.DST_PORT = port
		return rep

	def to_bytes(self):
		t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
		t += self.REP.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.RSV.to_bytes(1, byteorder = 'big', signed = False)
		t += self.ATYP.value.to_bytes(1, byteorder = 'big', signed = False)
		if self.ATYP == SOCKS5AddressType.DOMAINNAME:
			t += len(self.DST_ADDR).to_bytes(1, byteorder = 'big', signed = False)
			t += self.DST_ADDR.encode()
		else:	
			t += self.DST_ADDR.packed
		t += self.DST_PORT.to_bytes(2, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '== SOCKS5Reply ==\r\n'
		t += 'REP: %s\r\n' % repr(self.REP)
		t += 'ATYP: %s\r\n' % repr(self.ATYP)
		t += 'BIND_ADDR: %s\r\n' % repr(self.BIND_ADDR)
		t += 'BIND_PORT: %s\r\n' % repr(self.BIND_PORT)

		return t


class SOCKS5UDP:
	def __init__(self):
		self.RSV = None
		self.FRAG = None
		self.ATYP = None
		self.DST_ADDR = None
		self.DST_PORT = None
		self.DATA = None

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		rep = SOCKS5UDP()
		t = await read_or_exc(reader,2, timeout = timeout)
		rep.RSV = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.FRAG = SOCKS5ReplyType(int.from_bytes(t, byteorder = 'big', signed = False))
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.ATYP = SOCKS5AddressType(int.from_bytes(t, byteorder = 'big', signed = False))
		if rep.ATYP == SOCKS5AddressType.IP_V4:
			t = await read_or_exc(reader,4, timeout = timeout)
			rep.DST_ADDR = ipaddress.IPv4Address(t)
		elif rep.ATYP == SOCKS5AddressType.IP_V6:
			t = await read_or_exc(reader,16, timeout = timeout)
			rep.DST_ADDR = ipaddress.IPv6Address(t)

		elif rep.ATYP == SOCKS5AddressType.DOMAINNAME:
			t = await read_or_exc(reader,1, timeout = timeout)
			length = int.from_bytes(t, byteorder = 'big', signed = False)
			t = await read_or_exc(reader,length, timeout = timeout)
			rep.DST_ADDR = t.decode()

		t = await read_or_exc(reader,2, timeout = timeout)
		rep.DST_PORT = int.from_bytes(t, byteorder = 'big', signed = False)
		return rep

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5UDP.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		rep = SOCKS5UDP()
		rep.RSV = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		rep.FRAG = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		rep.ATYP = int.SOCKS5AddressType(buff.read(1), byteorder = 'big', signed = False)
		if rep.ATYP == SOCKS5AddressType.IP_V4:
			rep.DST_ADDR = ipaddress.IPv4Address(buff.read(4))
		elif rep.ATYP == SOCKS5AddressType.IP_V6:
			rep.DST_ADDR = ipaddress.IPv6Address(buff.read(16))
		elif rep.ATYP == SOCKS5AddressType.DOMAINNAME:
			length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
			rep.DST_ADDR = buff.read(length).decode()

		rep.DST_PORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		#be careful, not data length is defined in the RFC!!
		rep.DATA = buff.read()

	@staticmethod
	def construct(address, port, data, frag = 0):
		req = SOCKS5Request()
		req.RSV = 0
		req.FRAG = frag
		if isinstance(address, ipaddress.IPv4Address):
			req.ATYP = SOCKS5AddressType.IP_V4
			req.DST_ADDR = address
		elif isinstance(address, ipaddress.IPv6Address):
			req.ATYP = SOCKS5AddressType.IP_V6
			req.DST_ADDR = address
		elif isinstance(address, str):
			req.ATYP = SOCKS5AddressType.DOMAINNAME
			req.DST_ADDR = address

		req.DST_PORT = port
		req.DATA = data
		return req

	def to_bytes(self):
		t  = self.RSV.to_bytes(2, byteorder = 'big', signed = False)
		t += self.FRAG.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.ATYP.value.to_bytes(1, byteorder = 'big', signed = False)
		if self.ATYP == SOCKS5AddressType.DOMAINNAME:
			t += len(self.DST_ADDR).to_bytes(1, byteorder = 'big', signed = False)
			t += self.DST_ADDR.encode()
		else:	
			t += self.DST_ADDR.packed
		t += self.DST_PORT.to_bytes(2, byteorder = 'big', signed = False)
		t += self.DATA
		return t

def get_mutual_preference(preference, offered):
	# this is a commonly used algo when we need to determine the mutual option
	# which is both supported by the client and the server, in order of the
	# server's preference
	"""
	Generic function to determine which option to use from two lists of options offered by two parties.
	Returns the option that is mutual and in the highes priority of the preference
	:param preference: A list of options where the preference is set by the option's position in the list (lower is most preferred)
	:type preference: list
	:param offered: A list of options that the other party can offer
	:type offered: list
	:return: tuple
	"""
	clinet_supp = set(offered)
	server_supp = set(preference)
	common_supp = server_supp.intersection(clinet_supp)
	if common_supp is None:
		return None, None
	
	preferred_opt = None
	for srv_option in preference:
		for common_option in common_supp:
			if common_option == srv_option:
				preferred_opt = srv_option
				break
		else:
			continue
		break
	
	# getting index of the preferred option...
	preferred_opt_idx = 0
	for option in offered:
		if option == preferred_opt:
			# preferred_dialect_idx += 1
			break
		preferred_opt_idx += 1

	return preferred_opt, preferred_opt_idx

class SOCKS5Session:
	def __init__(self):
		self.current_state   = SOCKS5ServerState.NEGOTIATION
		self.allinterface = ipaddress.ip_address('0.0.0.0')
		self.supported_auth_types = [SOCKS5Method.PLAIN, SOCKS5Method.NOAUTH]
		self.mutual_auth_type = None
		self.auth_handler    = None
		self.client_transport= None
		self.creds = None
		self.proxy_closed = asyncio.Event()
		self.timeout = 60

	def __repr__(self):
		t  = '== SOCKS5Session ==\r\n'
		t += 'current_state:      %s\r\n' % repr(self.current_state)
		t += 'supported_auth_types: %s\r\n' % repr(self.supported_auth_types)
		t += 'mutual_auth_type: %s\r\n' % repr(self.mutual_auth_type)
		t += 'auth_handler: %s\r\n' % repr(self.auth_handler)
		t += 'client_transport: %s\r\n' % repr(self.client_transport)
		return t

class Socks5Packet:
	def __init__(self, session_id, data):
		self.session_id = session_id
		self.data = data

	def to_dict(self):
		t = {}
		t['session_id'] = self.session_id
		if self.data is None: #special case for closing socket
			t['data'] = None
		else:
			t['data'] = self.data.hex()
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_data(data):
		packet = json.loads(data)
		pdata = packet['data']
		if pdata is None:
			return Socks5Packet(packet['session_id'], None)
		else:
			return Socks5Packet(packet['session_id'], bytes.fromhex(pdata))

class FakeStreamReader:
	def __init__(self, in_queue):
		self.in_queue = in_queue
		self.in_buffer = b''
		self.is_closing = False

	def at_eof(self):
		return self.is_closing

	async def streamify_input(self):
		try:
			while True:
				data = await self.in_queue.get()
				if data is None:
					logger.debug('We are closing this line!')
					self.is_closing = True
				else:
					self.in_buffer += data
		except Exception as e:
			logger.exception('streamify_input')

	async def read(self, maxlen = -1):
		print('Read %d' % maxlen)
		
		while self.in_buffer == b'' and not self.is_closing:
			await asyncio.sleep(0.01)

		if maxlen == -1:
			data = self.in_buffer
			self.in_buffer = b''
			print('Read data: %s' % data)
			return data
		else:
			if len(self.in_buffer) >= maxlen:
				data = self.in_buffer[:maxlen]
				self.in_buffer = self.in_buffer[maxlen:]
				print('Read data: %s' % data)
				return data
			else:
				data = self.in_buffer
				self.in_buffer = b''
				print('Read data: %s' % data)
				return data

	async def readexactly(cnt):
		if len(self.in_buffer) >= cnt:
			data = self.in_buffer[:cnt]
			if cnt == 1:
				data = data.to_bytes(1, byteorder = 'big', signed = False)
			self.in_buffer = self.in_buffer[maxlen:]
			return data
		else:
			while not len(self.in_buffer) >= cnt:
				await asyincio.sleep(0.01)
			
			data = self.in_buffer[:cnt]
			if cnt == 1:
				data = data.to_bytes(1, byteorder = 'big', signed = False)
			self.in_buffer = self.in_buffer[maxlen:]
			return data

	async def run(self):
		asyncio.ensure_future(self.streamify_input())

class FakeStreamWriter:
	def __init__(self, session_id, out_queue):
		self.session_id = session_id
		self.out_queue = out_queue
		self.buffer = b''
		self.is_closing = False

	def write(self, data):
		if data == b'':
			self.is_closing = True
		self.buffer += data

	async def drain(self):
		data = self.buffer
		self.buffer = b''
		await self.out_queue.put(Socks5Packet(self.session_id, data))
		if self.is_closing:
			await self.out_queue.put(Socks5Packet(self.session_id, None))



class Socks5Server:
	def __init__(self, session_id, in_queue, out_queue):
		self.session_id = session_id
		self.in_queue = in_queue
		self.out_queue = out_queue
		self.session = SOCKS5Session()
		self.creader = FakeStreamReader(self.in_queue)
		self.cwriter = FakeStreamWriter(self.session_id, self.out_queue)

		self.in_buffer = b''

	async def parse_message(self, timeout=None):
		try:
			req = await asyncio.wait_for(SOCKS5CommandParser.from_streamreader(self.creader, self.session), timeout=timeout)
			return req
		except asyncio.TimeoutError:
			logger.debug('Timeout!')

	async def send(self, data):
		print('Sending putput data!')
		await self.out_queue.put(Socks5Packet(self.session_id, data))

	async def proxy_forwarder(self, reader, writer):
		while not self.session.proxy_closed.is_set():
			try:
				data = await asyncio.wait_for(reader.read(4096), timeout=self.session.timeout)
			except asyncio.TimeoutError:
				logger.debug('Timeout!')
				self.session.proxy_closed.set()
				break	
			
			if data == b'' or reader.at_eof():
				logger.debug('Connection closed!')
				self.session.proxy_closed.set()
				break
			
			try:
				writer.write(data)
				await asyncio.wait_for(writer.drain(), timeout=self.session.timeout)
			except asyncio.TimeoutError:
				logger.debug('Timeout!')
				self.session.proxy_closed.set()
				break

		try:
			await asyncio.wait_for(writer.drain(), timeout=self.session.timeout)
			if isinstance(writer, FakeStreamWriter):
				writer.write(b'')
				await writer.drain()
		except Exception as e:
			logger.exception('proxy finishing!')
		return

	async def run(self):
		asyncio.ensure_future(self.creader.run())
		try:
			while True:
				msg = await asyncio.wait_for(self.parse_message(), timeout = 30)
				#print(str(msg))
				if self.session.current_state == SOCKS5ServerState.NEGOTIATION:
					mutual, mutual_idx = get_mutual_preference(self.session.supported_auth_types, msg.METHODS)
					if mutual is None:
						logger.debug('No common authentication types! Client supports %s' % (','.join([str(x) for x in msg.METHODS])))
						print(msg.METHODS)
						t = await asyncio.wait_for(self.send(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOTACCEPTABLE).to_bytes()), timeout = 1)
						return
					logger.debug('Mutual authentication type: %s' % mutual)
					self.session.mutual_auth_type = mutual
					self.session.authHandler = SOCKS5AuthHandler(self.session.mutual_auth_type, self.session.creds) 

					if self.session.mutual_auth_type == SOCKS5Method.NOAUTH:
						self.session.current_state = SOCKS5ServerState.REQUEST # if no authentication is requred then we skip the auth part
					else:
						self.session.current_state = SOCKS5ServerState.NOT_AUTHENTICATED

					t = await asyncio.wait_for(self.send(SOCKS5NegoReply.construct(self.session.mutual_auth_type).to_bytes()), timeout = 1)

				elif self.session.current_state == SOCKS5ServerState.NOT_AUTHENTICATED:
					if self.session.mutual_auth_type == SOCKS5Method.PLAIN:
						status, creds = self.session.authHandler.do_AUTH(msg)
						if status:
							self.session.current_state = SOCKS5ServerState.REQUEST
							t = await asyncio.wait_for(self.send(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOAUTH).to_bytes()), timeout = 1)
						else:
							t = await asyncio.wait_for(self.send(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOTACCEPTABLE).to_bytes()), timeout = 1)
							return
					else:
						#put GSSAPI implementation here
						raise Exception('Not implemented!')

				elif self.session.current_state == SOCKS5ServerState.REQUEST:
					logger.debug('Remote client wants to connect to %s:%d' % (str(msg.DST_ADDR), msg.DST_PORT))
					if msg.CMD == SOCKS5Command.CONNECT:
						#in this case the server acts as a normal socks5 server
						proxy_reader, proxy_writer = await asyncio.wait_for(asyncio.open_connection(host=str(msg.DST_ADDR),port = msg.DST_PORT), timeout=1)
						logger.debug('Connected!')
						self.session.current_state = SOCKS5ServerState.RELAYING
						t = await asyncio.wait_for(self.send(SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED, self.session.allinterface, 0).to_bytes()), timeout = 1)
						asyncio.ensure_future(self.proxy_forwarder(proxy_reader, self.cwriter))
						asyncio.ensure_future(self.proxy_forwarder(self.creader, proxy_writer))

						await asyncio.wait_for(self.session.proxy_closed.wait(), timeout = None)
						return
					
					else:
						t = await asyncio.wait_for(SOCKS5Reply.construct(SOCKS5ReplyType.COMMAND_NOT_SUPPORTED, self.session.allinterface, 0).to_bytes(), timeout = 1)
						return				
		except Exception as e:
			logger.exception('Socks5Server error!')

class Socks5Module(CommsModule):
	def __init__(self, job_id, in_queue, out_queue):
		CommsModule.__init__(self, module_name, job_id, in_queue, out_queue, ModuleDesignation.AGENT)
		self.sessions = {} #session_id -> socks5server
		self.server_out_queue = asyncio.Queue()
	
	async def handle_socks5_out(self):
		try:
			while True:
				packet = await self.server_out_queue.get()

				print('Sending putput packet! ')
				await self.send_data(packet.to_json())
		except Exception as e:
			logger.exception('handle_socks5_out')
			return


	async def run(self):
		asyncio.ensure_future(self.handle_socks5_out())
		while True:
			data = await self.get_data()
			logger.debug('Got data! %s' % data)
			packet = Socks5Packet.from_data(data)
			if packet.session_id not in self.sessions:
				logger.debug('Creating new session!')
				in_queue = asyncio.Queue()
				server = Socks5Server(packet.session_id, in_queue, self.server_out_queue)
				self.sessions[packet.session_id] = server
				asyncio.ensure_future(server.run())
			
			await self.sessions[packet.session_id].in_queue.put(packet.data)


class Socks5ModuleServer(CommsModule):
	def __init__(self, job_id, in_queue, out_queue):
		CommsModule.__init__(self, module_name, job_id, in_queue, out_queue)
		self.sessions = {} #session_id -> writer

	async def handle_client_out(self):
		while True:
			try:
				data = await self.get_data()
				print('Data out')
				packet = Socks5Packet.from_data(data)
				if packet.session_id not in self.sessions:
					logger.debug('Unknown session id')
					continue
			
				if packet.data is None:
					#closing connection!
					try:
						await self.sessions[packet.session_id].drain()
						self.sessions[packet.session_id].close()
					except Exception as e:
						logger.exception('Socket closing!')
					
					del self.sessions[packet.session_id]
				else:
					try:
						self.sessions[packet.session_id].write(packet.data)
						await self.sessions[packet.session_id].drain()
					except Exception as e:
						logger.debug('session died :(')
						temp = self.sessions[packet.session_id]
						del self.sessions[packet.session_id]
						try:
							temp.close()
						except:
							pass

			except Exception as e:
				logger.exception('handle_client_out')
				continue

	async def handle_client_in(self,session_id,  reader):
		while True:
			try:
				data = await reader.read(4096)
				if data == b'' or reader.at_eof():
					await self.send_data(Socks5Packet(session_id, None).to_json())
					try:
						self.sessions[session_id].close()
					except:
						pass
					if session_id in self.sessions:
						del self.sessions[session_id]
					return
				else:
					await self.send_data(Socks5Packet(session_id, data).to_json())
			except Exception as e:
				logger.exception('handle_client_in')
				return


	async def handle_client(self, reader, writer):
		try:
			logger.debug('Client connected from %s:%d' % ( writer.get_extra_info('peername')))
			#creating new session
			session_id = str(uuid.uuid4())
			self.sessions[session_id] = writer
			asyncio.ensure_future(self.handle_client_in(session_id, reader))
			return
		except Exception as e:
			logger.exception('handle_client')
			return

	async def run(self):
		listen_ip = '127.0.0.1'
		listen_port = 8888
		asyncio.ensure_future(self.handle_client_out())
		#t = await asyncio.wait_for(asyncio.start_server(self.handle_client, listen_ip, listen_port), timeout = None)
		await asyncio.start_server(self.handle_client, listen_ip, listen_port)
		print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
