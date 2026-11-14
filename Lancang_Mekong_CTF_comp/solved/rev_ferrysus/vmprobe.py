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

gdb.Breakpoint('*0x%x' % (B + 0x10a9f))
gdb.execute('run')
n = 0
while n < 60:
    n += 1
    S = reg('sp')
    rbx = reg('rbx')
    p90 = u64(S + 0x90); p18 = u64(S + 0x18); pd0 = u64(S + 0xd0)
    print('ptr=0x%x end=0x%x  [90]=0x%x [18]=0x%x' % (rbx, pd0, p90, p18))
    print('   8stride:', mem(rbx, 16).hex(' '))
    print('   12stride:', mem(rbx, 24).hex(' '))
    gdb.execute('continue')
