import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def uq(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x11068))   # op4
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))
gdb.execute('run')
for k in range(6):
    pc = int(gdb.parse_and_eval('$pc')) - B
    S = int(gdb.parse_and_eval('$sp'))
    if pc == 0x11068:
        print('op4 stage=%d count=%d flag60=%d' % (
            uq(S + 0xc8) & 0xff, uq(S), uq(S + 0x60) & 1))
    else:
        print('  FAIL at op4 (flag was 0?)'); break
    gdb.execute('continue')
