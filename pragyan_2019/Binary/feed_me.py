

from pwn import *

def calc(random1, random2, random3):
	return ((random1 / 2) - (random2 / 2) + (random3 / 2), (random1 / 2) + (random2 / 2) - (random3 / 2), - (random1 / 2) + (random2 / 2) + (random3 / 2))

def solve():
	"""
	F + S = random1
	S + T = random2
	F + T = random3
	"""
	#p = process('./challenge1')
	p = remote('159.89.166.12', 9800)
	print(p.recvline())
	numbers = p.recvrepeat(1)
	random1, random2, random3, _ = numbers.split(';')
	random1 = int(random1)
	random2 = int(random2)
	random3 = int(random3)
	print("[*]", random1, random2, random3)
	first, second, third = calc(random1, random2, random3)
	response = "%010d"*3 % (first, second, third)
	print(response)
	p.sendline(response)
	res = p.recvrepeat(1)
	print(res)
	if "No" not in res:
		return
	p.close()
if __name__ == "__main__":
	while True:
		solve()
