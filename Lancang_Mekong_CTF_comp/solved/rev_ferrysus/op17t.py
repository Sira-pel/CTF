import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def uq(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def u(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10ad6))
gdb.execute('run')
for k in range(4):
    S = int(gdb.parse_and_eval('$sp'))
    stage = uq(S + 0xc8) & 0xff
    cnt = uq(S)
    arr = uq(S + 0x18)
    rbx = int(gdb.parse_and_eval('$rbx'))
    print('op17 stage=%d cnt=%d imm=0x%08x tag=%d C=%d' % (
        stage, cnt, u32(rbx), int(gdb.parse_and_eval('*(unsigned char*)%d' % (rbx + 5))), u16(rbx + 6)))
    if stage == 4:
        d = u(arr, 12 * cnt)
        for i in range(cnt):
            e = d[12*i:12*i+12]
            print('   [%d] p0=0x%08x w4=0x%04x C=0x%04x D=0x%02x' % (
                i, int.from_bytes(e[0:4],'little'), int.from_bytes(e[4:6],'little'),
                int.from_bytes(e[6:8],'little'), e[8]))
        break
    gdb.execute('continue')
