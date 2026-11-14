import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020

def u(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10de4))   # op10 setup: r9=item count
gdb.Breakpoint('*0x%x' % (B + 0x10ee3))   # post-step
gdb.Breakpoint('*0x%x' % (B + 0x10f07))   # reg mismatch
gdb.Breakpoint('*0x%x' % (B + 0x10f31))   # nibble fail
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))
gdb.execute('run')
hits = 0
while hits < 40:
    hits += 1
    pc = int(gdb.parse_and_eval('$pc')) - B
    S = int(gdb.parse_and_eval('$sp'))
    if pc == 0x10de4:
        print('op10: count(r9)=%d tag=%d C=%d mul=0x%08x' % (
            int(gdb.parse_and_eval('$r9')), int(gdb.parse_and_eval('*(unsigned char*)(%d+5)' % int(gdb.parse_and_eval('$rbx')))),
            int(gdb.parse_and_eval('*(unsigned short*)(%d+6)' % int(gdb.parse_and_eval('$rbx')))),
            int(gdb.parse_and_eval('*(unsigned int*)%d' % int(gdb.parse_and_eval('$rbx'))))))
    elif pc == 0x10ee3:
        i = int(gdb.parse_and_eval('$r14'))
        acc = int(gdb.parse_and_eval('$esi')) & 0xffffffff
        print('  i=%d acc=0x%08x' % (i, acc))
    elif pc in (0x10f07, 0x10f31):
        print('  >>> fail at %x' % pc); break
    elif pc == 0x11f6a:
        print('>>> VM FAIL'); break
    gdb.execute('continue')
