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

gdb.Breakpoint('*0x%x' % (B + 0x11b58))
gdb.Breakpoint('*0x%x' % (B + 0x11c76))
gdb.Breakpoint('*0x%x' % (B + 0x11d40))
gdb.execute('run')
for _ in range(20):
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x11b58:
        idx = reg('rcx') & 0xff
        print('[stage] id=%d  key=0x%08x  nrec=%d' % (idx, u64(S + 0xe4) & 0xffffffff, u64(S + 0x140)))
    elif pc == 0x11c76:
        print('   [xor] len(r15)=%d rec=0x%x ks=0x%x' % (reg('r15'), reg('r13'), reg('rbx')))
        print('     rec:', mem(reg('r13'), min(reg('r15'), 48)).hex(' '))
        print('     ks :', mem(reg('rbx'), min(reg('r15'), 48)).hex(' '))
    else:
        print('   [decrypted] len=%d %s' % (reg('r15'), mem(reg('r14'), min(reg('r15'), 48)).hex(' ')))
    gdb.execute('continue')
