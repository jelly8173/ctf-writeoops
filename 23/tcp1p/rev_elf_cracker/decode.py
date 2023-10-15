decode_table = []
for i in range(0,0x100):
  out = i
  while i>>1 > 0:
    i >>= 1
    out ^= i
  decode_table.append(out)

key = []
with open('key_enc_rev', 'rb') as keyf:
  key_enc_rev = keyf.read()
  key_enc = key_enc_rev[::-1]
  for i in range(len(key_enc)):
    key.append(decode_table.index(key_enc[i]))

text = []
with open('text_enc', 'rb') as textf:
  text_enc = textf.read()
  for i in range(len(text_enc)):
    text.append(key[i]^text_enc[i])

with open('text', 'wb') as texto:
  for i in range(len(text)):
    texto.write(text[i].to_bytes(1))