import gdb, re, struct

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
    except Exception:
        return b''

def u64(a):
    return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x10aa5))
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))
gdb.Breakpoint('*0x%x' % (B + 0x11b05))
gdb.Breakpoint('*0x%x' % (B + 0x11a7c))
gdb.execute('run')

n = 0
while n < 400:
    n += 1
    pc = reg('pc') - B
    if pc == 0x10aa5:
        d = mem(reg('rbx'), 8)
        op = d[4]
        S = reg('sp')
        acc = reg('rsi') & 0xffffffff
        cnt = u64(S)
        print('i op=%2d tag=%3d C=%5d imm=%08x acc=%08x cnt=%d' % (
            op, d[5], int.from_bytes(d[6:8], 'little'), int.from_bytes(d[0:4], 'little'), acc, cnt))
        if op in (10, 12, 13):
            ep = u64(S + 0x18)
            eb = mem(ep, cnt * 12)
            for k in range(cnt):
                e = eb[12*k:12*k+12]
                print('   ent%d %s' % (k, e.hex()))
    elif pc == 0x11a7c:
        print('  SUM cmp ecx=%d X=%d' % (reg('ecx') & 0xffff, reg('cx') if False else int(gdb.parse_and_eval('*(unsigned short*)($sp+0x84)'))))
    elif pc == 0x11f6a:
        print('VM FAIL acc=%08x' % (reg('rsi') & 0xffffffff))
        break
    elif pc == 0x11b05:
        S = reg('sp')
        print('STAGE END flag=%d key=%08x stage=%d' % (u64(S + 0xc0) & 0xff, u64(S + 0xe4) & 0xffffffff, u64(S + 0xc8) & 0xff))
    gdb.execute('continue')
