import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))

# handler entry addresses in the VM dispatch table order
HANDLERS = {1:0x10ac4, 2:0x11151, 3:0x10fd4, 4:0x11068, 5:0x10c07, 6:0x1120f, 7:0x1126d,
            8:0x110dd, 9:0x1132a, 10:0x10dab, 11:0x112ef, 12:0x10bfa, 13:0x10d57,
            14:0x11246, 15:0x10bb5, 16:0x1104b, 17:0x10ad6, 18:0x11172, 19:0x112a9,
            20:0x1137e, 21:0x11187, 22:0x11238, 23:0x11331, 24:0x113e8, 25:0x10f36}
for op, off in HANDLERS.items():
    gdb.Breakpoint('*0x%x' % (B + off))
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))
gdb.Breakpoint('*0x%x' % (B + 0x11af5))
gdb.execute('run')
log = []
n = 0
while n < 400:
    n += 1
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x11f6a:
        print('>>> FAIL after %d ops' % len(log))
        break
    if pc == 0x11af5:
        print('>>> stage complete, valid=%d' % (u64(S + 0xc0) & 0xff))
        log = []
        gdb.execute('continue')
        continue
    op = [k for k, v in HANDLERS.items() if v == pc]
    op = op[0] if op else '?'
    log.append(op)
    print('op%-2s' % op, end=' ')
    gdb.execute('continue')
print()
print('ops:', log)
