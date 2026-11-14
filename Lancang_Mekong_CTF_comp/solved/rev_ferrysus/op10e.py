import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x10ee3))
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))
gdb.Breakpoint('*0x%x' % (B + 0x11af5))
gdb.execute('run')
n = 0
while n < 200:
    n += 1
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x10ee3:
        i = reg('r14')
        print('  i=%d acc=0x%08x flag=%d reg=0x%08x %s' % (
            i, reg('esi') & 0xffffffff, u32(S + i*8 + 0x1b0), u32(S + i*8 + 0x1b4),
            'MATCH' if u32(S + i*8 + 0x1b0) != 1 or u32(S + i*8 + 0x1b4) == (reg('esi') & 0xffffffff) else 'MISMATCH'))
    elif pc == 0x11f6a:
        print('>>> FAIL'); break
    elif pc == 0x11af5:
        print('>>> stage ok valid=%d key=0x%08x' % (u32(S + 0xc0) & 0xff, u32(S + 0xe4)))
    gdb.execute('continue')
