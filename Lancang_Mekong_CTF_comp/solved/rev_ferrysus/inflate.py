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
    except Exception: return b''

gdb.Breakpoint('*0x%x' % (B + 0xf5d9))
gdb.execute('run')
for it in range(12):
    S = reg('sp')
    tag = u64(S + 0x70)
    print('== inflate call #%d disc=0x%x ptr=0x%x len=0x%x' % (it, tag, u64(S + 0x78), u64(S + 0x80)))
    if tag != 1:
        p = u64(S + 0x78); L = u64(S + 0x80)
        d = mem(p, L)
        print('   data len=%d' % len(d))
        print('   hex:', d.hex())
        if len(d) % 8 == 0:
            for k in range(len(d) // 8):
                e = d[8*k:8*k+8]
                print('     [%2d] op=%-2d tag=%-3d C=%-5d imm=0x%08x' % (
                    k, e[0], e[1], int.from_bytes(e[2:4], 'little'), int.from_bytes(e[4:8], 'little')))
    gdb.execute('continue')
