import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020

def uq(a):
    return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))

def u(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10dab))
gdb.execute('run')
# skip first op10 (stage 1)
gdb.execute('continue')
S = int(gdb.parse_and_eval('$sp'))
cnt = uq(S)
arr = uq(S + 0x18)
print('op10 stage2: count=%d arr=0x%x' % (cnt, arr))
d = u(arr, 12 * cnt)
for k in range(cnt):
    e = d[12*k:12*k+12]
    print('  [%d] p0=0x%08x w4=0x%04x C=0x%04x D=0x%02x' % (
        k, int.from_bytes(e[0:4],'little'), int.from_bytes(e[4:6],'little'),
        int.from_bytes(e[6:8],'little'), e[8]))
