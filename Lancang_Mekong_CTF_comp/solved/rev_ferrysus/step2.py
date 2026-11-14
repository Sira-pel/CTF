import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
WATCH = {0x11ed5, 0x11f00, 0x11f6a, 0x11af5, 0x1028e}

gdb.Breakpoint('*0x%x' % (B + 0x10538))
gdb.execute('run')
print('secloop r9=%d rbp=%d' % (reg('r9'), reg('rbp')))
log = []
hit = None
for i in range(4000):
    pc = reg('pc') - B
    log.append(pc)
    if pc in WATCH:
        hit = pc
        break
    gdb.execute('si')
print('hit', hex(hit) if hit else None)
for l in log[-30:]:
    print(hex(l))
