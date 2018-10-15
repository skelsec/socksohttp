import asyncio

html_data = """
<!DOCTYPE html>
<html>

<head>
</head>

<body>

<script>
function connect(){
	const server_url = document.getElementById('server_url').value;
	const agent_url = document.getElementById('agent_url').value;
	const ws_server = new WebSocket(server_url);
	const ws_agent = new WebSocket(agent_url);
	
	ws_server.onopen = function(event) {
		var label = document.getElementById('serverstatus');
		label.innerHTML = 'CONNECTED';
	};
	
	ws_agent.onopen = function(event) {
		var label = document.getElementById('agentstatus');
		label.innerHTML = 'CONNECTED';
	};

	ws_server.onmessage = function(event) {
		//console.log(e);
		//console.log('Server to client: ' + e.data);
		ws_agent.send(event.data);
	};

	ws_agent.onmessage = function(event) {
		//console.log(e);
		//console.log('Client to server: ' + e.data);
		ws_server.send(event.data);
	};
}
</script>

<h1>socksOhttp Javascript proxy</h1>

<strong>Server URL:</strong><br>
<input type="text" class="draw-border" id="server_url" size="35"><br>

<strong>Agent URL:</strong><br>
<input type="text" class="draw-border" id="agent_url" size="35"><br>
<br>

<button onclick="connect()">Connect</button> 
<br><br>

<strong>Server Status</strong>&#160;&#160;&#160;&#160;&#160;&#160;<label id="serverstatus">DISCONNECTED</label><br>
<strong>Agent Status</strong>&#160;&#160;&#160;&#160;&#160;&#160;<label id="agentstatus">DISCONNECTED</label><br>

</body>



</html>

"""

class FakeHTTPServer:
	"""
	Pls do not use this anywhere else, this is dirty and disgusting
	"""
	def __init__(self, listen_ip = '127.0.0.1', listen_port = '8444', logger = None):
		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.logger = logger
		self.name = '[FakeHTTPServer]'

	async def handle_client(self, reader, writer):
		try:
			self.logger.debug('%s Client connected from %s' % (self.name,  '%s:%d' % writer.get_extra_info('peername')))
			#only reading the header
			data = await reader.readuntil(b'\r\n\r\n')
			data = data.decode()
			
			hdr = [
				'HTTP/1.1 200 OK',
				'Server: Apache/2.2.14 (Win32)',
				'Content-Length: %d' % len(html_data),
				'Content-Type: text/html; charset=utf-8',
				'Connection: Closed',
			]
			response = '\r\n'.join(hdr) + '\r\n\r\n' + html_data
			
			writer.write(response.encode())
			await writer.drain()

			return
		except Exception as e:
			self.logger.debug('%s handle_client' % self.name)
			return

	async def run(self):
		server = await asyncio.start_server(self.handle_client, self.listen_ip, self.listen_port)
		addrs = '%s:%d' % server.sockets[0].getsockname()
		self.logger.info('%s is now listening on %s' % (self.name, addrs))
			
		#python3.7 has this awesome stuff but in 3.6 this functionality is missing :(
		#async with server:
		#	await server.serve_forever()
		asyncio.ensure_future(server.serve_forever())
		return
