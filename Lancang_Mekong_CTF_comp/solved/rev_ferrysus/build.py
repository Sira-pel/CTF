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

gdb.Breakpoint('*0x%x' % (B + 0x103a2))   # in the "read u64s from route" loop
gdb.Breakpoint('*0x%x' % (B + 0x104d1))
gdb.Breakpoint('*0x%x' % (B + 0x10538))
gdb.Breakpoint('*0x%x' % (B + 0x108aa))
gdb.Breakpoint('*0x%x' % (B + 0x10934))
gdb.Breakpoint('*0x%x' % (B + 0x10a10))
gdb.execute('run')
seen = 0
while seen < 40:
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x103a2:
        print('[route-read] iter=%d val=0x%x' % (u64(S + 0xc8), reg('rbx')))
    elif pc == 0x104d1:
        ln = u64(S + 0x170); p = u64(S + 0x168)
        print('[vec done] len=%d ptr=0x%x' % (ln, p))
        if p:
            d = mem(p, 8 * ln)
            print('   u64s:', [hex(int.from_bytes(d[8*i:8*i+8], 'little')) for i in range(ln)])
    elif pc == 0x10538:
        print('[sec loop] off(r9)=%d passlen=%d' % (reg('r9'), reg('rbp')))
    elif pc == 0x108aa:
        print('[sec end] r11(count)=%d' % reg('r11'))
    elif pc == 0x10934:
        print('[12B array] count=%d ptr=0x%x' % (reg('r15'), reg('rax')))
        p = u64(S + 0x18)
        d = mem(p, 12 * min(reg('r15'), 8))
        for k in range(min(reg('r15'), 8)):
            e = d[12*k:12*k+12]
            print('     [%d] %s  imm=0x%08x op=%d tag=%d C=0x%04x D=%d' % (
                k, e.hex(' '), int.from_bytes(e[0:4],'little'), e[4], e[5], int.from_bytes(e[6:8],'little'), e[8]))
    elif pc == 0x10a10:
        cnt = reg('rbx'); p = u64(S + 0x90)
        print('[vm arr] count=%d ptr=0x%x end=0x%x' % (cnt, p, p + 8*cnt))
        d = mem(p, 8 * cnt)
        print('    ', d.hex(' '))
        break
    seen += 1
    gdb.execute('continue')
