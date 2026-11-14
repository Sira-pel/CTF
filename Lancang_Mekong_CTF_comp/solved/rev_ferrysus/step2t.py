import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def uq(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x10e24))
gdb.execute('run')
gdb.execute('continue')   # skip stage-1 op10 entirely by continuing past first hit chain
# now in stage 2: print each step's inputs
for step_i in range(30):
    S = int(gdb.parse_and_eval('$sp'))
    i = int(gdb.parse_and_eval('$r14'))
    r10 = int(gdb.parse_and_eval('$r10'))
    acc = int(gdb.parse_and_eval('$esi')) & 0xffffffff
    print('i=%d acc=0x%08x item(p0=0x%08x,w4=0x%04x,C=0x%04x,D=0x%02x) stage=%d' % (
        i, acc, u32(r10 - 8), u16(r10 - 4), u16(r10 - 2),
        int(gdb.parse_and_eval('*(unsigned char*)%d' % r10)), uq(S + 0xc8) & 0xff))
    gdb.execute('continue')
    if int(gdb.parse_and_eval('$pc')) - B == 0x11f6a:
        print('  FAILED here'); break
