import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def reg(n): return int(gdb.parse_and_eval('$' + n))

gdb.Breakpoint('*0x%x' % (B + 0x101b0))
gdb.Breakpoint('*0x%x' % (B + 0x10538))
gdb.execute('run')
hits = 0
while hits < 20:
    hits += 1
    pc = reg('pc') - B
    if pc == 0x101b0:
        print('checker: rdi=0x%x(len %d) passptr=0x%x passlen=%d' % (reg('rdi'), reg('rsi'), reg('rdx'), reg('rcx')))
    else:
        print('secloop: r9=%d rbp=%d r13=0x%x' % (reg('r9'), reg('rbp'), reg('r13')))
    gdb.execute('continue')
