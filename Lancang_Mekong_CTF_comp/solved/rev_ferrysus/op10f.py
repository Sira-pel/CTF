import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))

for off in (0x10e24, 0x10e38, 0x10df5, 0x10f07, 0x10f0d, 0x10f23, 0x10f31, 0x11f6a):
    gdb.Breakpoint('*0x%x' % (B + off))
gdb.execute('run')
n = 0
while n < 100:
    n += 1
    pc = reg('pc') - B
    S = reg('sp'); r10 = reg('r10'); rbx = reg('rbx')
    if pc == 0x10e24:
        print('step i=%d acc=0x%08x passw4=0x%04x' % (reg('r14'), reg('esi') & 0xffffffff, u32(r10 - 8) & 0xffff))
    elif pc == 0x10e38:
        print('   mode? tag=%d  acc>>8&3=%d  passC=0x%04x' % (u8(rbx + 5), (reg('esi') >> 8) & 3, int(gdb.parse_and_eval('*(unsigned short*)%d' % (r10 - 2)))))
    elif pc == 0x10df5:
        print('   [mode2 nibble check] acc&0xf=0x%x D=0x%02x' % (reg('esi') & 0xf, u8(r10)))
    elif pc == 0x10f23:
        print('   [mode1 nibble check] acc>>28=0x%x D=0x%02x' % ((reg('esi') >> 28) & 0xf, u8(r10)))
    elif pc == 0x10f07:
        print('   >>> reg mismatch'); break
    elif pc == 0x10f31:
        print('   >>> nibble fail'); break
    else:
        print('>>> fail'); break
    gdb.execute('continue')
