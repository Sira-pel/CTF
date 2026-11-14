import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def memstr(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10a10))
gdb.execute('run')
S = reg('sp')
print('decoded array ptr = 0x%x' % u64(S + 0x1b8))
print('count rbx = %d' % reg('rbx'))
print('entries:', memstr(u64(S + 0x1b8), 12 * 4).hex(' '))
print('r12 = 0x%x  (first entry = ptr+8? )' % reg('r12'))
print('at r12:', memstr(reg('r12'), 24).hex(' '))
