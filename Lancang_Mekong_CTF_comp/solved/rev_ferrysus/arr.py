import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10dab))
gdb.execute('run')
S = reg('sp')
print('op10: imm=0x%08x tag=%d C=0x%04x' % (u32(reg('rbx')), int(gdb.parse_and_eval('*(unsigned char*)(%d+5)' % reg('rbx'))),
                                            u16(reg('rbx') + 6)))
print('n items(rsp[0])=%d' % u64(S))
p = u64(S + 0x18)
print('pass array ptr=0x%x' % p)
d = mem(p, 12 * 8)
for k in range(8):
    e = d[12*k:12*k+12]
    print('  [%d] %s  w4=0x%04x C=0x%04x p0=0x%08x D=0x%02x' % (
        k, e.hex(' '), int.from_bytes(e[0:2],'little'), int.from_bytes(e[2:4],'little'),
        int.from_bytes(e[4:8],'little'), e[8]))
