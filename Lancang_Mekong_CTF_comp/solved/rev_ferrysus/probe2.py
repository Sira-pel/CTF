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

gdb.Breakpoint('*0x%x' % (B + 0x10a10))
gdb.Breakpoint('*0x%x' % (B + 0x10aa5))
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))
gdb.Breakpoint('*0x%x' % (B + 0x11af5))
gdb.Breakpoint('*0x%x' % (B + 0x11fd4))
gdb.execute('run')
n = 0
while n < 400:
    n += 1
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x10a10:
        print('[setup] passcount(rbx)=%d  routecount(r15/r9)=?' % reg('rbx'))
        print('  passitems[1b8]=0x%x  copy[0x90]=0x%x' % (u64(S+0x1b8), u64(S+0x90)))
        p = u64(S + 0x1b8)
        if p:
            d = mem(p, 12 * 8)
            for k in range(8):
                e = d[12*k:12*k+12]
                print('    pasit[%d] %s imm=0x%08x w4=0x%04x(op=%d,tag=%d) w6=0x%04x D=0x%02x' % (
                    k, e.hex(' '), int.from_bytes(e[0:4],'little'),
                    int.from_bytes(e[4:6],'little'), e[4], e[5], int.from_bytes(e[6:8],'little'), e[8]))
    elif pc == 0x10aa5:
        r12 = reg('r12'); S = reg('sp')
        d = mem(r12, 8)
        if len(d) == 8:
            print('  VM: i=%d op=%d tag=%d C=0x%04x imm=0x%08x' % (
                u64(S), d[4], d[5], int.from_bytes(d[6:8],'little'), int.from_bytes(d[0:4],'little')))
    elif pc == 0x11f6a:
        print('  >>> VM FAIL'); break
    elif pc == 0x11af5:
        print('  >>> VM stage done'); 
    elif pc == 0x11fd4:
        print('  >>> FINAL'); break
    gdb.execute('continue')
