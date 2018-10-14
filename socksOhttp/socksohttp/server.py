import asyncio
from datetime import datetime
import uuid

from .comms import *
from . import logger
from .modules.echo import EchoModuleServer
from .modules.socks5 import Socks5ModuleServer

from .fakehttpserver import *


import websockets


class CommsClient:
	"""
	Class handles the client job communications
	"""
	def __init__(self, client_uuid, in_queue, out_queue):
		self.client_uuid = client_uuid
		self.connected_at = datetime.utcnow()
		self.last_seen_at = None
		
		self.in_queue = in_queue
		self.out_queue = out_queue

		self.interface_queue = asyncio.Queue()

		self.jobs = {} #jobid -> job_in_queue
		self.job_cmd_queue = asyncio.Queue()
		self.pending_jobs = {}

	async def create_job(self, module_name):
		logger.debug('Creating job for module %s' % repr(module_name))
		self.pending_jobs[module_name] = 1
		cmd = CreateJobCmd()
		cmd.job_name = module_name
		await self.job_cmd_queue.put(cmd)

	async def start_job(self, rply):
		if rply.job_name not in self.pending_jobs:
			logger.warning('Client replied to a job creating with a job that wasnt initiated on server!')
			return
		
		del self.pending_jobs[rply.job_name]
		if rply.job_name == 'echo':
			in_queue = asyncio.Queue()
			ems = EchoModuleServer(rply.job_id, in_queue, self.job_cmd_queue)
			self.jobs[rply.job_id] = in_queue
			asyncio.ensure_future(ems.run())

		elif rply.job_name == 'socks5':
			in_queue = asyncio.Queue()
			ems = Socks5ModuleServer(rply.job_id, in_queue, self.job_cmd_queue)
			self.jobs[rply.job_id] = in_queue
			asyncio.ensure_future(ems.run())

		else:
			logging.warning('Unknown module naem started on the agent!')
			return

		logger.debug('Started job for module %s' % repr(rply.job_name))


	async def listen_rplys(self):
		while True:
			rply = await self.in_queue.get()
			if isinstance(rply, JobRply):
				if rply.job_id in self.jobs:
					await self.jobs[rply.job_id].put(rply.job_data)
				else:
					logger.warning('Reply to an unknown job id!')
			elif isinstance(rply, CreateJobRply):
				await self.start_job(rply)
			elif isinstance(rply, StopJobRply):
				pass
			else:
				logger.warning('Unknown object type in client queue!')

	async def listen_cmds(self):
		while True:
			cmd = await self.job_cmd_queue.get()
			cmd.client_uuid = self.client_uuid
			await self.out_queue.put(cmd)

	async def run(self):
		asyncio.ensure_future(self.listen_rplys())
		asyncio.ensure_future(self.listen_cmds())

		await self.create_job('socks5')
		await self.interface_queue.get()



class CommsServer:
	def __init__(self, ws_ip, ws_port, with_proxyjs = False):
		self.ws_server = None
		self.ws_ip = ws_ip
		self.ws_port = ws_port

		self.with_proxyjs = with_proxyjs

		self.clients = {} #uuid -> CommsClient
		self.sessions = {} #uuid -> ws
		
		self.client_timeout = 20
		self.client_ping_interval = 60

		self.interface_queue = asyncio.Queue()

	async def keepalive(self, ws, client):
		logger.debug('keepalive starting')
		await asyncio.sleep(5)
		while True:
			# No data in 20 seconds, check the connection.
			try:
				pong_waiter = await ws.ping()
				await asyncio.wait_for(pong_waiter, timeout=self.client_timeout)
				logger.debug('Client still alive!')
				await asyncio.sleep(self.client_ping_interval)
			except asyncio.TimeoutError:
				logger.info('Client timed out, dropping client!')
				await client.in_queue.put('kill')
				return
			except Exception as e:
				logger.exception('Keepalive died!')
				return
				

	async def register_client(self, ws):
		"""
		Extend this function if more registration is needed
		"""
		try:
			client_uuid = str(uuid.uuid4())
			rc = RegisterCmd()
			rc.client_uuid = client_uuid
			msg = ClientCmd()
			msg.uuid = str(uuid.uuid4())
			msg.cmd = rc
			data = msg.to_msg()

			await ws.send(data)

			msg = await ws.recv()
			cr = ClientRply.from_msg(msg)
			if not isinstance(cr.rply, RegisterRply):
				raise Exception('Client sent wrong message! %s' % str(type(rply)))

			if cr.rply.client_uuid != client_uuid:
				raise Exception('Client returned different uuid! %s' % str(client_uuid))
			
			logger.debug('Client registered! %s' % client_uuid)
			client_in_queue = asyncio.Queue()
			client_out_queue = asyncio.Queue()
			cc = CommsClient(client_uuid, client_in_queue, client_out_queue)
			self.clients[client_uuid] = cc
			self.sessions[client_uuid] = ws
			asyncio.ensure_future(self.keepalive(ws, cc))
			return cc



		except Exception as e:
			logger.exception('Client from %s:%d failed to register!' % ws.remote_address)

	async def handle_client_out(self, ws, client):
		while True:
			cmd = await client.out_queue.get()
			msg = ClientCmd()
			msg.uuid = str(uuid.uuid4())
			msg.cmd = cmd
			data = msg.to_msg()

			await ws.send(data)


	async def handle_client_in(self, ws, client):
		while True:
			msg = await ws.recv()
			cr = ClientRply.from_msg(msg)
			cmd_uuid = cr.uuid
			await client.in_queue.put(cr.rply)

	
	async def handle_client(self, ws, path):
		logger.debug('Client connected from %s:%d' % ws.remote_address)
		cc = await self.register_client(ws)
		asyncio.ensure_future(self.handle_client_in(ws, cc))
		asyncio.ensure_future(self.handle_client_out(ws, cc))
		asyncio.ensure_future(cc.run())

		
		"""
		TESTING PART!!!
		"""
		await self.interface_queue.get()


		logger.debug('Client has been dealt with.')


		


	def run(self):
		logger.debug('Starting server!')
		"""
		ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		ssl_context.load_cert_chain(
			pathlib.Path(__file__).with_name('localhost.pem'))

		start_server = websockets.serve(
			hello, 'localhost', 8765, ssl=ssl_context)
		"""
		try:
			if self.with_proxyjs == True:
				fh = FakeHTTPServer(listen_ip = '0.0.0.0', listen_port = 8080,logger = logger)
				asyncio.ensure_future(fh.run())
			self.ws_server = websockets.serve(self.handle_client, self.ws_ip, self.ws_port)
			return self.ws_server
		except Exception as e:
			logger.exception('Failed to start server!')

if __name__ == '__main__':
	cs = CommsServer('0.0.0.0', 6666)
	start_server = cs.run()
	asyncio.get_event_loop().run_until_complete(start_server)
	asyncio.get_event_loop().run_forever()