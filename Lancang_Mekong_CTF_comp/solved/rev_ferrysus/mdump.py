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
p = u64(S + 0x90)
print('count=%d array=0x%x' % (cnt, p))
raw = mem(p, 8 * cnt)
print('array bytes:', raw.hex(' '))
for k in range(cnt):
    e = raw[8*k:8*k+8]
    if len(e) < 8: break
    print('  [%d] %s  -> imm=0x%08x op=0x%02x tag=0x%02x C=0x%04x' % (
        k, e.hex(' '), int.from_bytes(e[0:4],'little'), e[4], e[5], int.from_bytes(e[6:8],'little')))
