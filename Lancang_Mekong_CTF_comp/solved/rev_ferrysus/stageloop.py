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

gdb.Breakpoint('*0x%x' % (B + 0x11b58))
gdb.Breakpoint('*0x%x' % (B + 0x11d40))
gdb.execute('run')
for _ in range(20):
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x11b58:
        idx = reg('rcx') & 0xff
        print('[stage-loop] stage_id=%d  validflag92=%d key=0x%x' % (idx, u64(S + 0xc0), u64(S + 0xe4) & 0xffffffff))
        vec = u64(S + 0x138)
        for k in range(3):
            print('   rec%d: ptr=0x%x len=%d' % (k, u64(vec + 0x18*k + 8), u64(vec + 0x18*k + 16)))
    elif pc == 0x11d40:
        print('   decrypted stage buf=0x%x len=%d' % (reg('r14'), reg('r15')))
        print('   ', mem(reg('r14'), reg('r15')).hex())
    gdb.execute('continue')
