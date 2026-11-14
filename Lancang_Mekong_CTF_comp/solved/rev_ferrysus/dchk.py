import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))

for off in (0x10ee3, 0x10f0d, 0x10df5, 0x10f23, 0x10f31, 0x11f6a, 0x11af5):
    gdb.Breakpoint('*0x%x' % (B + off))
gdb.execute('run')
n = 0
while n < 80:
    n += 1
    pc = reg('pc') - B
    S = reg('sp'); r10 = reg('r10'); rbx = reg('rbx')
    if pc == 0x10ee3:
        print('i=%d acc=0x%08x' % (reg('r14'), reg('esi') & 0xffffffff))
    elif pc == 0x10f0d:
        print('   nibsel=%d' % u8(reg('rax') + 6))
    elif pc == 0x10df5:
        print('   mode2: acc&0xf=0x%x D=0x%02x %s' % (reg('esi') & 0xf, u8(r10),
              'ok' if (reg('esi') & 0xf) == u8(r10) else 'FAIL'))
    elif pc == 0x10f23:
        print('   mode1: acc>>28=0x%x D=0x%02x %s' % ((reg('esi') >> 28) & 0xf, u8(r10),
              'ok' if ((reg('esi') >> 28) & 0xf) == u8(r10) else 'FAIL'))
    elif pc == 0x11f6a:
        print('>>> FAIL'); break
    elif pc == 0x11af5:
        print('>>> stage ok'); break
    gdb.execute('continue')
