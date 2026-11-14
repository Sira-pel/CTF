import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10561))
gdb.Breakpoint('*0x%x' % (B + 0x105a1))
gdb.execute('run')
for _ in range(6):
    pc = reg('pc') - B
    if pc == 0x10561:
        r9 = reg('r9')
        print('[parse] off=%d  sec_hdr=%s  stage=%d count=%d' % (
            r9, mem(reg('r13') + r9, 8).hex(' '),
            u8(reg('r13') + r9 + 2), u8(reg('r13') + r9 + 3)))
    else:
        print('   [count] rsi=%d' % reg('rsi'))
    gdb.execute('continue')
