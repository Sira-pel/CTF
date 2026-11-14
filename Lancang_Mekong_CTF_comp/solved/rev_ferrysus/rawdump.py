import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x108f3))   # r12 = decoded pass array
gdb.Breakpoint('*0x%x' % (B + 0x10934))
gdb.execute('run')
for _ in range(4):
    pc = reg('pc') - B
    if pc == 0x108f3:
        p = reg('r12')
        print('[pass array] ptr=0x%x count(r11)=%d' % (p, reg('r11')))
        print('  bytes:', mem(p, 12 * max(1, reg('r11'))).hex(' '))
    else:
        S = reg('sp')
        p = u64(S + 0x18)
        print('[12B copy] count(r15)=%d ptr=0x%x' % (reg('r15'), p))
        print('  bytes:', mem(p, 12 * max(1, reg('r15'))).hex(' '))
    gdb.execute('continue')
