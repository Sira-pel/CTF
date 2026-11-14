import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

HAND = {1:0x10ac4, 2:0x11151, 3:0x10fd4, 4:0x11068, 5:0x10c07, 6:0x1120f, 7:0x1126d,
        8:0x110dd, 9:0x1132a, 10:0x10dab, 11:0x112ef, 12:0x10bfa, 13:0x10d57,
        14:0x11246, 15:0x10bb5, 16:0x1104b, 17:0x10ad6, 18:0x11172, 19:0x112a9,
        20:0x1137e, 21:0x11187, 22:0x11238, 23:0x11331, 24:0x113e8, 25:0x10f36}

gdb.Breakpoint('*0x%x' % (B + 0x10a9f))     # dispatch: rbx=cur item
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))
gdb.Breakpoint('*0x%x' % (B + 0x11af5))
gdb.execute('run')
n = 0
while n < 500:
    n += 1
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x10a9f:
        r12 = reg('r12')
        d = mem(r12, 8)
        if len(d) != 8: break
        op, tag = d[4], d[5]
        C = int.from_bytes(d[6:8], 'little'); imm = int.from_bytes(d[0:4], 'little')
        print('op=%-2d tag=%-3d C=%-5d imm=0x%08x  i=%d acc=0x%08x cnt=%d' % (
            op, tag, C, imm, u64(S) & 0xff, reg('rsi') & 0xffffffff, u64(S + 0x98)))
        if op == 3:
            p = u64(S + 0x18)
            print('    op3 pre-array(3xi):', mem(p, 36).hex(' ') if p else '-')
    elif pc == 0x11f6a:
        print('>>> FAIL'); break
    elif pc == 0x11af5:
        print('>>> stage end valid=%d key=0x%08x' % (u64(S + 0xc0) & 0xff, u64(S + 0xe4) & 0xffffffff))
        break
    gdb.execute('continue')
