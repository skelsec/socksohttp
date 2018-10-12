import asyncio
from ..comms import *

module_name = 'echo'

class EchoModuleServer(CommsModule):
	def __init__(self, job_id, in_queue, out_queue):
		CommsModule.__init__(self, module_name, job_id, in_queue, out_queue)

	async def run(self):
		while True:
			data = 'HELLO AGENT!'
			await self.send_data(data)
			rdata = await self.get_data()
			print('Data recieved : %s' % data)
			await asyncio.sleep(5)


class EchoModule(CommsModule):
	def __init__(self, job_id, in_queue, out_queue):
		CommsModule.__init__(self, module_name, job_id, in_queue, out_queue, ModuleDesignation.AGENT)

	async def run(self):
		while True:
			data = await self.get_data()
			print('Data recieved : %s' % data)
			await self.send_data(data)
			logger.debug('Reply sent!')