import gdb, re

gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020

def reg(n):
    return int(gdb.parse_and_eval('$' + n))

def mem(a, n):
    try:
        return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception as e:
        return b''

for off in (0x10561, 0x11f00, 0x11ed5, 0x10a10, 0x10aa5, 0x11f6a, 0x11b05, 0x1028e):
    gdb.Breakpoint('*0x%x' % (B + off))

gdb.execute('run')
for _ in range(8):
    pc = reg('pc') - B
    print('HIT', hex(pc))
    if pc == 0x10561:
        print('  sec', mem(reg('r13') + reg('r9'), 24).hex(), 'expect stage', reg('r14') & 0xff, 'passlen', reg('rbp'))
    elif pc == 0x10a10:
        S = reg('sp')
        cnt = reg('rbx')
        p = int(gdb.parse_and_eval('*(unsigned long*)%d' % (S + 0x90)))
        print('  count', cnt, 'prog', mem(p, min(cnt, 4) * 8).hex())
    elif pc == 0x10aa5:
        d = mem(reg('rbx'), 8)
        print('  insn', d.hex(), 'op', d[4] if d else None, 'acc', hex(reg('rsi') & 0xffffffff))
    elif pc == 0x1028e:
        print('  ret', reg('ebx') & 0xff)
        break
    elif pc in (0x11f00, 0x11ed5, 0x11f6a, 0x11b05):
        print('  fail/commit path')
        if pc == 0x11f6a:
            d = mem(reg('rbx'), 8)
            print('  insn', d.hex() if d else None)
    gdb.execute('continue')
