import asyncio
from datetime import datetime
import uuid

from .comms import *
from . import logger
from .modules.echo import EchoModule
from .modules.socks5 import Socks5Module

import websockets


class CommsAgentClient:
	def __init__(self, client_uuid, in_queue, out_queue):
		self.client_uuid = client_uuid
		self.connected_at = datetime.utcnow()
		self.last_seen_at = None
		
		self.in_queue = in_queue
		self.out_queue = out_queue

		self.modules = {} #jobid -> job_in_queue
		self.modules_cmd_queue = asyncio.Queue()
		self.modules_ctr = Counter()

	async def create_job(self, module_name):
		logger.debug('Creating job %s' % module_name)
		try:
			if module_name == 'echo':
				job_id = self.modules_ctr.get_next()
				in_queue = asyncio.Queue()
				em = EchoModule(job_id, in_queue, self.modules_cmd_queue)
				asyncio.ensure_future(em.run())

				self.modules[job_id] = in_queue

				rply = CreateJobRply()
				rply.job_name = module_name
				rply.job_id = job_id
				await self.modules_cmd_queue.put(rply)

			if module_name == 'socks5':
				job_id = self.modules_ctr.get_next()
				in_queue = asyncio.Queue()
				em = Socks5Module(job_id, in_queue, self.modules_cmd_queue)
				asyncio.ensure_future(em.run())

				self.modules[job_id] = in_queue

				rply = CreateJobRply()
				rply.job_name = module_name
				rply.job_id = job_id
				await self.modules_cmd_queue.put(rply)

			else:
				logger.warning('Unknown job to create! %s' % module_name)
				return 


		except Exception as e:
			logger.exception('create_job')

	async def listen_server_cmds(self):
		try:
			while True:
				cmd = await self.in_queue.get()
				if isinstance(cmd, JobCmd):
					if cmd.job_id in self.modules:
						await self.modules[cmd.job_id].put(cmd.job_data)
					else:
						logger.warning('Reply to an unknown job id!')
			
				elif isinstance(cmd, CreateJobCmd):
					logger.debug('Got command!')
					await self.create_job(cmd.job_name)
			
				elif isinstance(cmd, StopJobCmd):
					pass
		except Exception as e:
			logger.exception('listen_server_cmds')

	async def listen_module_rplys(self):
		try:
			while True:
				rply = await self.modules_cmd_queue.get()
				rply.client_uuid = self.client_uuid
				await self.out_queue.put(rply)
		except Exception as e:
			logger.exception('listen_module_rplys')

	async def run(self):
		try:
			asyncio.ensure_future(self.listen_server_cmds())
			t = await asyncio.wait_for(self.listen_module_rplys(), timeout = None)
			logger.info('Client exiting')
			
		except Exception as e:
			logger.exception('run')


class CommsAgentServer:
	def __init__(self, url):
		self.url = url
		self.uuid = None

	async def register(self, ws):
		msg = await ws.recv()
		cc = ClientCmd.from_msg(msg)
		logger.debug('CMD recieved! %s' % str(type(cc)))

		client_uuid = cc.cmd.client_uuid
		rply = RegisterRply()
		rply.client_uuid = client_uuid
		msg = ClientRply()
		msg.uuid = cc.uuid
		msg.rply = rply
		data = msg.to_msg()

		await ws.send(data)
		client_in_queue = asyncio.Queue()
		client_out_queue = asyncio.Queue()
		return CommsAgentClient(client_uuid, client_in_queue, client_out_queue)

		logger.debug('Registration succseeded!')
	
	async def handle_client_out(self, ws, client):
		while True:
			rply = await client.out_queue.get()
			msg = ClientRply()
			msg.uuid = str(uuid.uuid4())
			msg.rply = rply
			data = msg.to_msg()

			await ws.send(data)

	async def handle_client_in(self, ws, client):
		while True:
			msg = await ws.recv()
			logger.debug('handle_client_in Got command!')
			cr = ClientCmd.from_msg(msg)
			cmd_uuid = cr.uuid
			await client.in_queue.put(cr.cmd)

	async def run(self):
		try:
			async with websockets.connect(self.url) as ws:
				client = await self.register(ws)
				asyncio.ensure_future(self.handle_client_in(ws, client))
				asyncio.ensure_future(self.handle_client_out(ws, client))
				await client.run()
			
		except Exception as e:
			logger.exception('Error in main loop!')
			return