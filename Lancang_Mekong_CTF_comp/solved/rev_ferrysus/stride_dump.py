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

gdb.Breakpoint('*0x%x' % (B + 0x105f2))    # after reading C from section header
gdb.Breakpoint('*0x%x' % (B + 0x10a10))    # VM array ready
gdb.execute('run')
for _ in range(10):
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x105f2:
        print('[C read] sec_off=%d count(rsi)=%d' % (reg('r9'), reg('rsi')))
        base = reg('r9')
        print('   sec hdr:', mem(reg('r13') + base, 8).hex(' '))
    else:
        cnt = reg('rbx'); p = u64(S + 0x90)
        print('[vm] count=%d arr=0x%x' % (cnt, p))
        print('   ', mem(p, 8 * cnt).hex(' '))
        break
    gdb.execute('continue')
