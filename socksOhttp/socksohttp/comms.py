import abc
import zlib
import json
import enum
from datetime import datetime

from .AES import AESModeOfOperationCFB, Encrypter, Decrypter
from . import logger

key = b'AAAAAAAAAAAAAAAA'
iv = b'\x11'*16

class Counter:
	def __init__(self, start_no = 0):
		self.current = start_no

	def get_next(self):
		ctr = self.current
		self.current += 1
		return ctr

class ModuleDesignation(enum.Enum):
	SERVER = enum.auto()
	AGENT = enum.auto()

class CommsModule:
	def __init__(self, module_name, job_id, in_queue, out_queue, designation = ModuleDesignation.SERVER):
		self.module_name = module_name
		self.job_id = job_id
		self.in_queue = in_queue
		self.out_queue = out_queue
		self.started_at = datetime.utcnow()
		self.designation = designation
	
	async def get_data(self):
		data = await self.in_queue.get()
		return data

	async def send_data(self, data):
		if self.designation == ModuleDesignation.SERVER:
			cmd = JobCmd()
			cmd.job_id = self.job_id
			cmd.job_data = data
			await self.out_queue.put(cmd)
		else:
			cmd = JobRply()
			cmd.job_id = self.job_id
			cmd.job_data = data
			await self.out_queue.put(cmd)

class CommsModuleStreaming:
	def __init__(self, module_name, job_id, in_queue, out_queue, designation = ModuleDesignation.SERVER):
		self.module_name = module_name
		self.job_id = job_id
		self.in_queue = in_queue
		self.out_queue = out_queue
		self.started_at = datetime.utcnow()
		self.designation = designation

		self.in_buffer = b''

		asyncio.ensure_future(self.get_data())

	async def read(self, maxlen = -1):
		if maxlen == -1:
			data = self.in_buffer
			self.in_buffer = b''
			return data
		else:
			if len(self.in_buffer) >= maxlen:
				data = self.in_buffer[maxlen]
				self.in_buffer = self.in_buffer[maxlen:]
				return data
			else:
				data = self.in_buffer
				self.in_buffer = b''
				return data

	async def readexactly(cnt):
		if len(self.in_buffer) >= cnt:
			data = self.in_buffer[maxlen]
			self.in_buffer = self.in_buffer[maxlen:]
			return data
		else:
			while not len(self.in_buffer) >= cnt:
				await asyincio.sleep(0.01)
			
			data = self.in_buffer[maxlen]
			self.in_buffer = self.in_buffer[maxlen:]
			return data

	
	async def get_data(self):
		while True:
			data = await self.in_queue.get()
			self.in_buffer += bytes.fromhex(data)

	async def send_data(self, data):
		if self.designation == ModuleDesignation.SERVER:
			cmd = JobCmd()
			cmd.job_id = self.job_id
			cmd.job_data = data
			await self.out_queue.put(cmd)
		else:
			cmd = JobRply()
			cmd.job_id = self.job_id
			cmd.job_rply = data
			await self.out_queue.put(cmd)


class ClientCmd:
	__metaclass__ = abc.ABCMeta
	def __init__(self):		
		self.uuid = None
		self.cmd = None
		self.with_encryption = False
		self.with_compression = False

	@abc.abstractmethod
	def to_json(self):
		pass

	@abc.abstractmethod
	def from_json(self):
		pass
	
	def to_msg(self):
		data = self.cmd.to_json()
		if self.with_compression:
			cdata = zlib.compress(data.encode(), 9)
		else:
			cdata = data.encode()

		if self.with_encryption:
			encrypter = Encrypter(AESModeOfOperationCFB(key, iv)) #ovbiously change this
			edata = encrypter.feed(cdata)
			edata +=  encrypter.feed()
			return json.dumps({'uuid': self.uuid, 'data': edata.hex()})
		else:
			return json.dumps({'uuid': self.uuid, 'data': cdata.hex()})

	@staticmethod
	def from_msg(msg, with_encryption = False, with_compression = False):
		temp = json.loads(msg)
		if with_encryption:
			a = Decrypter(AESModeOfOperationCFB(key, iv)) #ovbiously change this
			ddata = a.feed(bytes.fromhex(temp['data']))
			ddata += a.feed()

		else:
			ddata = bytes.fromhex(temp['data'])

		if with_compression:
			data = zlib.decompress(ddata).decode()
		else:
			data = ddata
		
		raw_d = json.loads(data)
		if raw_d['cmd_id'] in int2cmd:
			cmd = int2cmd[raw_d['cmd_id']].from_json(raw_d)
			cc = ClientCmd()
			cc.uuid = temp['uuid']
			cc.cmd = cmd
			return cc
		else:
			raise Exception('Unknown/malformed command!')

class OKCmd:
	def __init__(self):
		self.cmd_id = 0

	def to_dict(self):
		t = {}
		t['cmd_id'] = self.cmd_id
		return t

	def to_json(self):
		return to_json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = OKCmd()
		return cmd
	
class ErrorCmd:
	def __init__(self):
		self.cmd_id = 1
		self.error_data = None

	def to_dict(self):
		t = {}
		t['cmd_id'] = self.cmd_id
		t['error_data'] = self.client_uuid
		return t

	def to_json(self):
		return to_json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = ErrorCmd()
		cmd.error_data = data['error_data']
		return cmd

class RegisterCmd:
	def __init__(self):
		self.cmd_id = 3
		self.client_uuid = None

	def to_dict(self):
		t = {}
		t['cmd_id'] = self.cmd_id
		t['client_uuid'] = self.client_uuid
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = RegisterCmd()
		cmd.client_uuid = data['client_uuid']
		return cmd

class CreateJobCmd:
	def __init__(self):
		self.cmd_id = 4
		self.client_uuid = None
		self.job_name = None

	def to_dict(self):
		t = {}
		t['cmd_id'] = self.cmd_id
		t['job_name'] = self.job_name
		t['client_uuid'] = self.client_uuid
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = CreateJobCmd()
		cmd.job_name = data['job_name']
		cmd.client_uuid = data['client_uuid']
		return cmd

class StopJobCmd:
	def __init__(self):
		self.cmd_id = 5
		self.client_uuid = None
		self.job_id = None

	def to_dict(self):
		t = {}
		t['cmd_id'] = self.cmd_id
		t['client_uuid'] = self.client_uuid
		t['job_id'] = self.job_id
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = StopJobCmd()
		cmd.job_id = data['job_id']
		cmd.client_uuid = data['client_uuid']
		return cmd

class JobCmd:
	def __init__(self):
		self.cmd_id = 6
		self.client_uuid = None
		self.job_id = None
		self.job_data = None #must be string!

	def to_dict(self):
		t = {}
		t['cmd_id'] = self.cmd_id
		t['client_uuid'] = self.client_uuid
		t['job_id'] = self.job_id
		t['job_data'] = self.job_data
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = JobCmd()
		cmd.job_id = data['job_id']
		cmd.job_data = data['job_data']
		cmd.client_uuid = data['client_uuid']
		return cmd


class ClientRply:
	def __init__(self):
		self.uuid = None
		self.rply = None
		self.with_encryption = False
		self.with_compression = False
	
	@abc.abstractmethod
	def to_json(self):
		pass

	@abc.abstractmethod
	def from_json(self):
		pass

	def to_msg(self):
		data = self.rply.to_json()
		if self.with_compression:
			cdata = zlib.compress(data.encode(), 9)
		else:
			cdata = data.encode()
		if self.with_encryption:
			encrypter = Encrypter(AESModeOfOperationCFB(b'AAAAAAAAAAAAAAAA', iv = b'\x11'*16)) #ovbiously change this
			edata = encrypter.feed(cdata)
			edata +=  encrypter.feed()
			return json.dumps({'uuid': self.uuid, 'data': edata.hex()})
		else:
			return json.dumps({'uuid': self.uuid, 'data': cdata.hex()})
		
	@staticmethod
	def from_msg(msg, with_encryption = False, with_compression = False):
		temp = json.loads(msg)
		if with_encryption:
			decrypter = Decrypter(AESModeOfOperationCFB(b'AAAAAAAAAAAAAAAA', iv = b'\x11'*16)) #ovbiously change this
			ddata = decrypter.feed(bytes.fromhex(temp['data']))
			ddata += decrypter.feed()
		else:
			ddata = bytes.fromhex(temp['data'])
		if with_compression:
			data = zlib.decompress(ddata).decode()
		else:
			data = ddata
		raw_d = json.loads(data)
		if raw_d['rply_id'] in int2cmd:
			cr = ClientRply()
			cr.uuid = temp['uuid']
			cr.rply = int2rply[raw_d['rply_id']].from_json(raw_d)
			return cr
		else:
			raise Exception('Unknown/malformed command!')

class RegisterRply:
	def __init__(self):
		self.rply_id = 3
		self.client_uuid = None

	def to_dict(self):
		t={}
		t['rply_id'] = self.rply_id
		t['client_uuid'] = self.client_uuid
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = RegisterRply()
		cmd.client_uuid = data['client_uuid']
		return cmd

class OKRply:
	def __init__(self):
		self.rply_id = 0

	def to_dict(self):
		t={}
		t['rply_id'] = self.rply_id
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = OKRply()
		return cmd

class ErrorRply:
	def __init__(self):
		self.rply_id = 1
		self.error_data = None

	def to_dict(self):
		t = {}
		t['rply_id'] = self.cmd_id
		t['error_data'] = self.client_uuid
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = ErrorRply()
		cmd.error_data = data['error_data']
		return cmd

class CreateJobRply:
	def __init__(self):
		self.rply_id = 4
		self.job_name = None
		self.job_id = None

	def to_dict(self):
		t = {}
		t['rply_id'] = self.rply_id
		t['job_name'] = self.job_name
		t['job_id'] = self.job_id
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = CreateJobRply()
		cmd.job_name = data['job_name']
		cmd.job_id = data['job_id']
		return cmd

class StopJobRply:
	def __init__(self):
		self.rply_id = 5
		self.job_id = None

	def to_dict(self):
		t = {}
		t['rply_id'] = self.rply_id
		t['job_id'] = self.job_id
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = StopJobRply()
		cmd.job_id = data['rply_id']
		return cmd

class JobRply:
	def __init__(self):
		self.rply_id = 6
		self.job_id = None
		self.job_data = None #must be string!

	def to_dict(self):
		t = {}
		t['rply_id'] = self.rply_id
		t['job_id'] = self.job_id
		t['job_data'] = self.job_data
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	@staticmethod
	def from_json(data):
		cmd = JobRply()
		cmd.job_id = data['job_id']
		cmd.job_data = data['job_data']
		return cmd

int2cmd = {
	0 : OKCmd,
	1 : ErrorCmd,
	3 : RegisterCmd,
	4 : CreateJobCmd,
	5 : StopJobCmd,
	6 : JobCmd
}

int2rply = {
	0 : OKRply,
	1 : ErrorRply,
	3 : RegisterRply,
	4 : CreateJobRply,
	5 : StopJobRply,
	6 : JobRply
}