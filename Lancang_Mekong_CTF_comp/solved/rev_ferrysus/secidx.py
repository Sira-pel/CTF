import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x10538))   # section loop head: r9 = offset
gdb.execute('run')
for _ in range(10):
    S = reg('sp')
    print('[sec] off=%d  count(rsi)=%d stage=%d X=0x%x H=0x%x' % (
        reg('r9'), reg('rsi'), u8(reg('r13') + reg('r9') + 2),
        u16(reg('r13') + reg('r9') + 4), u8(reg('r13') + reg('r9') + 6)))
    gdb.execute('continue')
