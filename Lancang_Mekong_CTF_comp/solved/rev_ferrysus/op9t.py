import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def uq(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x1132a))   # op9 handler
gdb.execute('run')
gdb.execute('continue')
S = int(gdb.parse_and_eval('$sp'))
rbx = int(gdb.parse_and_eval('$rbx'))
print('stage2 op9 imm=0x%08x  rsi(before)=0x%08x  rsp[0]=%d' % (
    int(gdb.parse_and_eval('*(unsigned int*)%d' % rbx)), int(gdb.parse_and_eval('$rsi')) & 0xffffffff, uq(S)))
gdb.execute('si')
print('after op9: rsi=0x%08x' % (int(gdb.parse_and_eval('$rsi')) & 0xffffffff))
