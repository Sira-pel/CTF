import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))

gdb.Breakpoint('*0x%x' % (B + 0x10680))
gdb.execute('run')
for i in range(8):
    print('iter%d: r15=0x%x r11=%d r9=%d r14=%d rdi=0x%x rbp=0x%x r13=0x%x' % (
        i, reg('r15'), reg('r11'), reg('r9'), reg('r14'), reg('rdi'), reg('rbp'), reg('r13')))
    gdb.execute('continue')
