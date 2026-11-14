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

gdb.Breakpoint('*0x%x' % (B + 0x10333))
gdb.Breakpoint('*0x%x' % (B + 0x10538))
gdb.Breakpoint('*0x%x' % (B + 0x11d40))
gdb.Breakpoint('*0x%x' % (B + 0x11d74))
gdb.execute('run')
n = 0
while n < 40:
    n += 1
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x10333:
        print('[stage-outer] stage=%d pass_off=%d' % (u64(S + 0xc8) & 0xff, u64(S + 0xac if False else 0x9c0) & 0xffffffff))
    elif pc == 0x10538:
        print('[section] sec_off=%d passlen=%d' % (reg('r9'), reg('rbp')))
    elif pc == 0x11d40:
        print('[decrypt done] len=%d' % reg('r15'))
    elif pc == 0x11d74:
        print('[vm start] stage=%d prog_entries=0x%x' % (u64(S + 0xc8) & 0xff, u64(S + 0x18)))
    gdb.execute('continue')
