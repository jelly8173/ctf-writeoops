We given two binaries: elf-cracker and flag

Looking into flag binary it seems that code section contain gibberish

Quickly skimming through elf-cracker binary reveals encrypt function that is called on `.text` section. Encryption key is read from /dev/urandom so it should be stored somewhere in order for challenge to be solvable. As always, I was too lazy to completely reverse the function so I start looking sideways

To test how it works I made simple hello-world C program, compiled it and fed as input to elf-cracker. Then compared sha256 hash with original binary to be certain that something is changed

Next put it into vbindiff and found that `.text` section is changed (that was expected). What I was looking for is the encryption key stored somewhere in the binary, and it was there: block of seemingly random data with the same size as `.text` secion!

I tried to xor first byte of it with encrypted data, but it does not work, so it must be something more about it

I pushed elf-cracker into gdb, set break at encrypt function and traced, looking for input data transformations. Indeed it was xored with blob read from /dev/urandom. After that each byte of a key is xored in a loop with itself shifted 1 bit right until shifted value is not 0 and stored in some buf in reverse order

From here on I extracted encrypted blob and key from flag file:

```sh
dd if=flag of=key_enc_rev bs=1 skip=6128 count=1045
dd if=flag of=text_enc bs=1 skip=4256 count=1045
```

Then build quite hacky py script to decode it (see decrypt.py) and put it back again:

```sh
dd if=flag of=p1 bs=1 count=4256
dd if=flag of=p3 bs=1 skip=5301
cat p1 text p3 > flag2
```

Run that binary and you'll be welcomed with fake flag:

```sh
rev_elf_cracker$ ./flag2
FAKE{well_done_man_but_its_just_a_fake_just_more_steps_again_to_the_flag_letgoo_ganbatte_朗}
```

At the end of main function there is an assignment of 0 to local variably and then immediately after that check if it is equal to 1 and brunch around big block of code. I manually patched this branch instruction with NOPs and here is the flag:

```
rev_elf_cracker$ ./flag2
GG you've reached the final steps, so heres the gift: TCP1P{bLud_Ju5t_W4st3d_his_t1me_fOR_pL4y1ng_CTF_and_h4v3nt_t0uch3d_gra55_f0r_A_W33k}
```