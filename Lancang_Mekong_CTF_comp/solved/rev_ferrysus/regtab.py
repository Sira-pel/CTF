import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10ee3))
gdb.execute('run')
S = reg('sp')
for i in range(3):
    print('--- step i=%d acc=0x%08x' % (reg('r14'), reg('esi') & 0xffffffff))
    print('   regtable @rsp+0x1b0:', mem(S + 0x1b0, 96).hex(' '))
    print('   op14 table @rsp+0x160:', mem(S + 0x160, 64).hex(' '))
    print('   nibble tab @rsp+0x38 :', mem(S + 0x38, 32).hex(' '))
    gdb.execute('continue')
