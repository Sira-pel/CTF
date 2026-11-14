import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
print('BASE=0x%x' % B)

gdb.Breakpoint('*0x%x' % (B + 0x10538))
gdb.execute('run')
print('at secloop, r9=%d rbp=%d' % (reg('r9'), reg('rbp')))
# single step until pc in {11ed5, 11f00, 11af5} or 400 steps
log = []
for i in range(600):
    pc = reg('pc')
    dis = gdb.execute('x/i 0x%x' % pc, to_string=True).strip()
    log.append('%x  %s' % (pc - B, dis.split('\t')[-1] if '\t' in dis else dis))
    if (pc - B) in (0x11ed5, 0x11f00):
        print('STOPPED at %x' % (pc - B))
        break
    gdb.execute('si')
for l in log[-40:]:
    print(l)
