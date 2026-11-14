import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020

def uq(a):
    return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x10a10))
gdb.Breakpoint('*0x%x' % (B + 0x10dab))
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))
gdb.execute('run')
for _ in range(20):
    pc = int(gdb.parse_and_eval('$pc')) - B
    S = int(gdb.parse_and_eval('$sp'))
    if pc == 0x10a10:
        print('[vm-setup] stageid=%d  progcount(rbx)=%d  progarray(rsp+0x90)=0x%x' % (
            uq(S + 0xc8) & 0xff, int(gdb.parse_and_eval('$rbx')), uq(S + 0x90)))
        print('           itemcount(rsp+0)=%d itemarray(rsp+0x18)=0x%x' % (uq(S), uq(S + 0x18)))
    elif pc == 0x10dab:
        print('[op10] itemcount(rsp+0)=%d itemarray=0x%x stageid=%d' % (uq(S), uq(S + 0x18), uq(S + 0xc8) & 0xff))
    else:
        print('>>> VM FAIL'); break
    gdb.execute('continue')
