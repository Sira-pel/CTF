import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def uq(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x10ef4))
gdb.execute('run')
# skip stage1 op10's six comparisons
for _ in range(8):
    gdb.execute('continue')
S = int(gdb.parse_and_eval('$sp'))
i = int(gdb.parse_and_eval('$r14'))
print('stage2 op10 first compare: i=%d  flag=%d  val=0x%08x  acc=0x%08x' % (
    i, u32(S + i*8 + 0x1b0), u32(S + i*8 + 0x1b4), int(gdb.parse_and_eval('$esi')) & 0xffffffff))
print('regtab:', ' '.join(hex(u32(S + 0x1b0 + 8*k)) for k in range(10)))
