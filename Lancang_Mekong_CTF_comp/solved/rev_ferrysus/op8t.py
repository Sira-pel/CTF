import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x11a78))   # op8 compare
gdb.Breakpoint('*0x%x' % (B + 0x11a7c))   # op8 exit
gdb.Breakpoint('*0x%x' % (B + 0x11a84))   # op8 fail jump
gdb.execute('run')
for _ in range(6):
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x11a78:
        print('[op8] cx(sum)=0x%04x  X(rsp+0x84)=0x%04x' % (reg('ecx') & 0xffff, u16(S + 0x84)))
    else:
        print('hit %x' % pc)
    gdb.execute('continue')
