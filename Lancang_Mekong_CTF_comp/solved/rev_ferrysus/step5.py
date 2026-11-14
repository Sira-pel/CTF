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
gdb.execute('run')
S = reg('sp')
cnt = reg('rbx')
base = u64(S + 0x90)
print('count=%d base=0x%x stage=%d' % (cnt, base, u64(S + 0x5c) & 0xffffffff))
data = mem(base, 8 * cnt)
print('raw:', data.hex(' '))
print()
for k in range(cnt):
    e = data[8 * k:8 * k + 8]
    if len(e) < 8: break
    a = int.from_bytes(e[0:4], 'little')
    op = e[4]; tag = e[5]; C = int.from_bytes(e[6:8], 'little')
    print('  [%2d] imm=0x%08x op=%-2d tag=%-3d C=0x%04x   (%s)' % (k, a, op, tag, C, e.hex(' ')))
