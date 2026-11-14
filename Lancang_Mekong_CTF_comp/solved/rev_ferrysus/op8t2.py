import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x11a7c))
gdb.execute('run')
S = reg('sp')
print('sum(cx)=0x%04x  X=0x%04x' % (reg('ecx') & 0xffff, u16(S + 0x84)))
print('pass array ptr = 0x%x' % (int(gdb.parse_and_eval('*(unsigned long*)%d' % (S + 0x18))) if False else 0))
print('items:', mem(int(gdb.parse_and_eval('*(unsigned long*)%d' % (S + 0x18))), 7*12).hex(' '))
