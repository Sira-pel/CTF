import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020

gdb.Breakpoint('*0x%x' % (B + 0x11a7c))
gdb.execute('run')
for k in range(4):
    S = int(gdb.parse_and_eval('$sp'))
    cx = int(gdb.parse_and_eval('$ecx')) & 0xffff
    X = int(gdb.parse_and_eval('*(unsigned short*)%d' % (S + 0x84)))
    print('hit %d: computed=0x%04x  X=0x%04x  %s' % (k + 1, cx, X, 'EQUAL' if cx == X else 'DIFF'))
    gdb.execute('continue')
