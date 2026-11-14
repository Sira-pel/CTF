import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020

def uq(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x10e24))
gdb.Breakpoint('*0x%x' % (B + 0x10ee3))
gdb.Breakpoint('*0x%x' % (B + 0x10f07))
gdb.Breakpoint('*0x%x' % (B + 0x10f31))
gdb.Breakpoint('*0x%x' % (B + 0x10df5))
gdb.execute('run')
gdb.execute('continue')   # skip stage 1 op10
n = 0
while n < 30:
    n += 1
    pc = int(gdb.parse_and_eval('$pc')) - B
    S = int(gdb.parse_and_eval('$sp'))
    r10 = int(gdb.parse_and_eval('$r10'))
    i = int(gdb.parse_and_eval('$r14'))
    if pc == 0x10e24:
        print('step i=%d acc=0x%08x item.p0=0x%08x item.w4=0x%04x item.C=0x%04x' % (
            i, int(gdb.parse_and_eval('$esi')) & 0xffffffff, u32(r10 - 8), u16(r10 - 4), u16(r10 - 2)))
    elif pc == 0x10ee3:
        print('   post acc=0x%08x  regtab[%d]: flag=%d val=0x%08x' % (
            int(gdb.parse_and_eval('$esi')) & 0xffffffff, i,
            u32(S + i*8 + 0x1a8), u32(S + i*8 + 0x1ac)))
    elif pc == 0x10df5:
        print('   nibble mode2: acc&f=0x%x  D=0x%02x' % (int(gdb.parse_and_eval('$esi')) & 0xf, u8(r10)))
    elif pc in (0x10f07, 0x10f31):
        print('   >>> fail at %x' % pc); break
    gdb.execute('continue')
