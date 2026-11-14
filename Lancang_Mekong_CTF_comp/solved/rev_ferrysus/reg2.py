import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def uq(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x10ef4))
gdb.execute('run')
# count how many comparisons happen
seen = 0
while seen < 20:
    seen += 1
    S = int(gdb.parse_and_eval('$sp'))
    i = int(gdb.parse_and_eval('$r14'))
    stage = uq(S + 0xc8) & 0xff
    flag = u32(S + i * 8 + 0x1b0)
    val = u32(S + i * 8 + 0x1b4)
    acc = int(gdb.parse_and_eval('$esi')) & 0xffffffff
    print('stage=%d i=%d flag=%d want=0x%08x have=0x%08x' % (stage, i, flag, val, acc))
    if stage == 2 and i == 0:
        print('  regtab stage2:', [hex(u32(S + k * 8 + 0x1b0)) for k in range(8)])
        print('  vals        :', [hex(u32(S + k * 8 + 0x1b4)) for k in range(8)])
        break
    gdb.execute('continue')
