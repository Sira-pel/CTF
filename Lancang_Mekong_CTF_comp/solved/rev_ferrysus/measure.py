import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10604))
gdb.Breakpoint('*0x%x' % (B + 0x10680))
gdb.execute('run')
print('[10604] count(rsi)=%d r14=%d r9(off)=%d r13=0x%x' % (reg('rsi'), reg('r14'), reg('r9'), reg('r13')))
print('   passlen(rbp)=%d' % reg('rbp'))
for i in range(4):
    print('[10680 %d] r15=0x%x r11=%d r14=%d rdi=0x%x' % (i, reg('r15'), reg('r11'), reg('r14'), reg('rdi')))
    gdb.execute('continue')
