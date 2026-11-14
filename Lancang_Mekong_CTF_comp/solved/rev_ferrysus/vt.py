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

gdb.Breakpoint('*0x%x' % (B + 0x10aa5))
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))
gdb.Breakpoint('*0x%x' % (B + 0x11af5))
gdb.Breakpoint('*0x%x' % (B + 0x11fd4))
gdb.execute('run')
n = 0
while n < 600:
    n += 1
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x10aa5:
        rbx = reg('rbx')
        d = mem(rbx, 8)
        if len(d) != 8: break
        print('i=%-3d op=%-2d tag=%-2d C=0x%04x imm=0x%08x  acc=0x%08x' % (
            u64(S) & 0xff, d[4], d[5], int.from_bytes(d[6:8],'little'),
            int.from_bytes(d[0:4],'little'), reg('rsi') & 0xffffffff))
    elif pc == 0x11f6a:
        print('>>> FAIL'); break
    elif pc == 0x11af5:
        print('>>> stage done  valid=%d stage=%d key=0x%08x' % (u64(S+0xc0) & 0xff, u64(S+0xc8) & 0xff, u64(S+0xe4) & 0xffffffff))
    elif pc == 0x11fd4:
        print('>>> FINAL r8=%d rbp=%d' % (reg('r8'), reg('rbp'))); break
    gdb.execute('continue')
