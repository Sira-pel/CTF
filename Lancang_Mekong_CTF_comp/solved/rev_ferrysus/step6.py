import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))

gdb.Breakpoint('*0x%x' % (B + 0x10538))
gdb.execute('run')
log = []
WATCH = {0x11ed5, 0x11f00, 0x11f6a, 0x108aa, 0x10a10}
hit = None
for i in range(20000):
    pc = reg('pc') - B
    log.append(pc)
    if pc in WATCH and i > 0:
        hit = pc
        break
    gdb.execute('si')
print('hit', hex(hit))
# compress: print only the distinct addresses since last
prev = None
for l in log:
    if l != prev:
        print(hex(l))
    prev = l
