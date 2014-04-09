import Mumble_pb2, socket, ssl, struct, sys, select
from datetime import datetime
from threading import Thread

ca_file = 'mumble-ca.crt'
payloads = {
	0: Mumble_pb2.Version,
	1: Mumble_pb2.UDPTunnel,
	2: Mumble_pb2.Authenticate,
	3: Mumble_pb2.Ping,
	4: Mumble_pb2.Reject,
	5: Mumble_pb2.ServerSync,
	6: Mumble_pb2.ChannelRemove,
	7: Mumble_pb2.ChannelState,
	8: Mumble_pb2.UserRemove,
	9: Mumble_pb2.UserState,
	10: Mumble_pb2.BanList,
	11: Mumble_pb2.TextMessage,
	12: Mumble_pb2.PermissionDenied,
	13: Mumble_pb2.ACL,
	14: Mumble_pb2.QueryUsers,
	15: Mumble_pb2.CryptSetup,
	16: Mumble_pb2.ContextActionModify,
	17: Mumble_pb2.ContextAction,
	18: Mumble_pb2.UserList,
	19: Mumble_pb2.VoiceTarget,
	20: Mumble_pb2.PermissionQuery,
	21: Mumble_pb2.CodecVersion,
	22: Mumble_pb2.UserStats,
	23: Mumble_pb2.RequestBlob,
	24: Mumble_pb2.ServerConfig,
	25: Mumble_pb2.SuggestConfig
}

def savecert():
	sock = ssl.wrap_socket(
		socket.socket(socket.AF_INET,
			socket.SOCK_STREAM), 
		ssl_version=ssl.PROTOCOL_TLSv1)

	# Connect to server without checking cert
	try:
		sock.connect(('voip.generic.ly', 64738))
	except ssl.SSLError:
		pass
	else:
		# Save cert to ca file
		c = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
		with open(ca_file, 'a') as certfile:
			certfile.write(c)

	sock.close()

def recv(s):
	# Payload prefix
	prefix = s.recv(6)
	if (len(prefix) <= 0):
		return (-1, None)

	type, length = struct.unpack('>hL', prefix)

	# Receive payload
	data = s.recv(length)
	if (len(data) <= 0):
		return (-1, None)

	# Return protobuf obj
	obj = payloads[type]()
	try:
		obj.ParseFromString(data)
		return (type, obj)
	except:
		return (type, None)

def send(s, payload):
	type = 0
	data = payload.SerializeToString()
	length = len(data)

	# Find type no.
	for t in payloads:
		if isinstance(payload, payloads[t]):
			type = t
			break

	s.send(struct.pack('>hL', type, length) + data)

def main():
	if (len(sys.argv) != 4):
		print('Usage: ' + sys.argv[0] + ' <host> <username> <password>')
		return

	_, host, username, password = sys.argv

	sock = ssl.wrap_socket(
		socket.socket(socket.AF_INET,
			socket.SOCK_STREAM), 
		ca_certs='mumble-ca.crt',
		cert_reqs=ssl.CERT_REQUIRED,
		ssl_version=ssl.PROTOCOL_TLSv1)

	try:
		sock.connect((host, 64738))
	except ssl.SSLError as e:
		sock.close()
		print('Server certificate unknown.')
		if raw_input('Wanna save it?').lower() == 'y':
			savecert()
		return main() # Re-call main because lazy

	print('Connected.')

	print('Exchanging versions')
	recv(sock) # Read server version
	ver = payloads[0]()
	ver.version = 66053 # 1.2.5
	ver.release = '1.2.5-233-gafa6ee4'
	ver.os = 'Mumbot'
	ver.os_version = 'v0.1'
	send(sock, ver) # Send Mumbot version

	print('Authenticating')
	auth = payloads[2]()
	auth.username = username
	auth.password = password
	send(sock, auth) # Authenticate

	t, crypt = recv(sock)
	if t == 4: # Reject
		print('Authentication rejected.')
		sock.close()
		return
	else:
		# Start UDP thread
		print('Authenticated')
	
	print('Syncing with server')
	while True:
		t, o = recv(sock)
		if t == 5: # ServerSync
			print('Finished syncing')
			print('Welcome message: ' + o.welcome_text)
			break

	recv(sock) # Discard ServerConfig

	# Main loop
	ping = 10
	timer = datetime.now()
	while True:
		ready = select.select([sock], [], [], ping)
		if ready[0]:
			t, o = recv(sock)
			if t in [1, 3]:
				pass # Ignore TCP voip tunneling and pings
			else:
				print(o) # Print interesting things

		if (datetime.now() - timer).seconds >= ping:
			send(sock, payloads[3]()) # Send empty Ping payload
			timer = datetime.now()


main()