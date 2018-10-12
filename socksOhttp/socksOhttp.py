import logging

from socksohttp.server import *
from socksohttp.client import *
from socksohttp import logger


if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Socks5 over HTTP')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity, can be stacked')

	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'mode'

	server_group = subparsers.add_parser('server', help='Server mode')
	server_group.add_argument('listen_ip', help='IP to listen on')
	server_group.add_argument('listen_port', type=int, help='port for the server')
	
	agent_group = subparsers.add_parser('agent', help='Agent mode')
	agent_group.add_argument('url', help='URL to connect to')

	args = parser.parse_args()
	print(args)

	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
		wslogger = logging.getLogger('websockets')
		wslogger.setLevel(logging.ERROR)
		wslogger.addHandler(logging.StreamHandler())
		
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
		logger.setLevel(logging.INFO)
		wslogger = logging.getLogger('websockets')
		wslogger.setLevel(logging.INFO)
		wslogger.addHandler(logging.StreamHandler())
		
	else:
		logging.basicConfig(level=1)
		logger.setLevel(logging.DEBUG)
		wslogger = logging.getLogger('websockets')
		wslogger.setLevel(logging.DEBUG)
		wslogger.addHandler(logging.StreamHandler())


	if args.mode == 'server':
		logging.debug('Starting server mode')
		cs = CommsServer(args.listen_ip, int(args.listen_port))
		start_server = cs.run()
		asyncio.get_event_loop().run_until_complete(start_server)
		asyncio.get_event_loop().run_forever()

	elif args.mode == 'agent':
		logging.debug('Starting agent mode')
		ca = CommsAgentServer(args.url)
		asyncio.get_event_loop().run_until_complete(ca.run())
		logging.debug('Agent exited!')