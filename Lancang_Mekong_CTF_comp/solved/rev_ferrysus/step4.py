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
    except Exception as e: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10a9f))
gdb.execute('run')
S = reg('sp')
print('r12 = 0x%x   rbx = %d' % (reg('r12'), reg('rbx')))
for name, off in [('0x90', 0x90), ('0x98', 0x98), ('0xd0', 0xd0), ('0x1b0', 0x1b0), ('0x1b8', 0x1b8), ('0x1c0', 0x1c0), ('0x60', 0x60), ('0x48', 0x48), ('0x5c', 0x5c)]:
    print('  [rsp+%s] = 0x%x (%d)' % (name, u64(S + off), u64(S + off)))
p = reg('r12')
print('mem @ r12 :', memstr(p, 40).hex(' '))
print('mem @ 0x90ptr:', memstr(u64(S + 0x90), 40).hex(' '))
print('regs [rsp+0xf0..]:', memstr(S + 0xf0, 64).hex(' '))
