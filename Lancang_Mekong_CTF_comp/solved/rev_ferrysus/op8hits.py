import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020

def u(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x110dd))
gdb.execute('run')
for hit in range(3):
    S = int(gdb.parse_and_eval('$sp'))
    cnt = int(gdb.parse_and_eval('*(unsigned long*)%d' % S))
    arr = int(gdb.parse_and_eval('*(unsigned long*)%d' % (S + 0x18)))
    X = int(gdb.parse_and_eval('*(unsigned short*)%d' % (S + 0x84)))
    tag = int(gdb.parse_and_eval('*(unsigned char*)%d' % (int(gdb.parse_and_eval('$rbx')) + 5)))
    print('== op8 hit %d: count=%d tag=%d X=0x%x arr=0x%x' % (hit + 1, cnt, tag, X, arr))
    d = u(arr, 12 * cnt)
    for k in range(cnt):
        e = d[12*k:12*k+12]
        print('   [%d] w4=0x%04x C=0x%04x' % (k, int.from_bytes(e[4:6],'little'), int.from_bytes(e[6:8],'little')))
    gdb.execute('continue')
