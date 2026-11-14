import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020

gdb.Breakpoint('*0x%x' % (B + 0x11151))
gdb.execute('run')
S = int(gdb.parse_and_eval('$sp'))
print('item_count =', int(gdb.parse_and_eval('*(unsigned long*)%d' % S)))
print('H@rsp+0x37 =', int(gdb.parse_and_eval('*(unsigned char*)%d' % (S + 0x37))))
rbx = int(gdb.parse_and_eval('$rbx'))
print('op2 tag =', int(gdb.parse_and_eval('*(unsigned char*)%d' % (rbx + 5))))
print('op2 C   =', int(gdb.parse_and_eval('*(unsigned short*)%d' % (rbx + 6))))
