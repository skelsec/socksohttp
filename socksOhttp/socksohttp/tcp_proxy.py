import asyncio
import logging

class AioTCPProxy:
	def __init__(self, reader1, writer1, reader2, writer2, name = '[AioTCPProxy]', logger = None, timeout = 60):
		self.reader1 = reader1
		self.writer1 = writer1
		self.addrs1 =  '%s:%s' % self.writer1.get_extra_info('peername')
		self.reader2 = reader2
		self.writer2 = writer2
		self.addrs2 =  '%s:%s' % self.writer2.get_extra_info('peername')
		self.proxy_closed = asyncio.Event()
		self.timeout = timeout
		self.name = name
		self.logger = logger
		self.log_data = True

		if not self.logger:
			self.logger = logging.get_logger()

	async def proxy_forwarder1(self):
		"""
		connects reader1 to writer2
		"""
		while not self.proxy_closed.is_set():
			try:
				data = await asyncio.wait_for(self.reader1.read(4096), timeout=self.timeout)
			except Exception as e:
				self.logger.debug('%s [%s -> %s] Reader error!' % (self.name, self.addrs1, self.addrs2))
				self.proxy_closed.set()
				break

			if data == b'' or self.reader1.at_eof():
				self.logger.debug('%s [%s -> %s] Reader closed the connection!' % (self.name, self.addrs1, self.addrs2))
				self.proxy_closed.set()
				break

			if self.log_data == True:
				self.logger.debug('%s [%s -> %s] Data: %s' % (self.name, self.addrs1, self.addrs2, data))
			
			try:
				self.writer2.write(data)
				await asyncio.wait_for(self.writer2.drain(), timeout=self.timeout)
			except Exception as e:
				self.logger.debug('%s [%s -> %s] write error!' % (self.name, self.addrs1, self.addrs2))
				self.proxy_closed.set()
				break

		try:
			await asyncio.wait_for(self.writer2.drain(), timeout=self.timeout)
		except Exception as e:
			logger.exception('proxy finishing!')
			self.proxy_closed.set()
		return

	async def proxy_forwarder2(self):
		"""
		connects reader2 to writer1
		"""
		while not self.proxy_closed.is_set():
			try:
				data = await asyncio.wait_for(self.reader2.read(4096), timeout=self.timeout)
			except Exception as e:
				self.logger.exception('%s [%s -> %s] Reader error!' % (self.name, self.addrs2, self.addrs1))
				self.proxy_closed.set()
				break

			if data == b'' or self.reader2.at_eof():
				self.logger.debug('%s [%s -> %s] Reader closed the connection!' % (self.name, self.addrs2, self.addrs1))
				self.proxy_closed.set()
				break

			if self.log_data == True:
				self.logger.debug('%s [%s -> %s] Data: %s' % (self.name, self.addrs1, self.addrs2, data))
			
			try:
				self.writer1.write(data)
				await asyncio.wait_for(self.writer1.drain(), timeout=self.timeout)
			except Exception as e:
				self.logger.exception('FakeHTTPProxy [%s -> %s] write error!' % (self.addrs2, self.addrs1))
				self.proxy_closed.set()
				break

		try:
			await asyncio.wait_for(self.writer1.drain(), timeout=self.timeout)
		except Exception as e:
			logger.exception('proxy finishing!')
			self.proxy_closed.set()
		return


	async def run(self):
		asyncio.ensure_future(self.proxy_forwarder1())
		asyncio.ensure_future(self.proxy_forwarder2())

