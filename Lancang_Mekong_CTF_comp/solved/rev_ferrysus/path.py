import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
WATCH = [0x101b0, 0x10212, 0x1022f, 0x1052a if False else 0x102a2, 0x10538, 0x108aa, 0x10a10,
         0x11ed5, 0x11f00, 0x11f6a, 0x11af5, 0x11fd4, 0x1028e]
for off in WATCH:
    gdb.Breakpoint('*0x%x' % (B + off))
gdb.execute('run')
for _ in range(40):
    pc = reg('pc') - B
    print('-> hit', hex(pc))
    gdb.execute('continue')
