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
cnt = reg('rbx'); p = u64(S + 0x90)
print('VM program (%d items) @0x%x:' % (cnt, p))
d = mem(p, 8 * cnt)
for k in range(cnt):
    e = d[8*k:8*k+8]
    print('  [%2d] op=%-2d tag=%-2d C=0x%04x imm=0x%08x' % (
        k, e[0], e[1], int.from_bytes(e[2:4],'little'), int.from_bytes(e[4:8],'little')))
