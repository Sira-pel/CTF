import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))

for off in (0x10ee3, 0x10f07, 0x10f31, 0x10f6a, 0x10df5, 0x11f6a):
    gdb.Breakpoint('*0x%x' % (B + off))
gdb.execute('run')
n = 0
while n < 60:
    n += 1
    pc = reg('pc') - B
    r10 = reg('r10'); rbx = reg('rbx'); r14 = reg('r14')
    if pc == 0x10ee3:
        print('[chk] i=%d acc=0x%08x regflag=%d regval=0x%08x  passD=0x%02x' % (
            r14, reg('esi') & 0xffffffff,
            u32(reg('rsp') + r14 * 8 + 0x1b0), u32(reg('rsp') + r14 * 8 + 0x1b4),
            u8(r10) if r10 > 0x1000 else 0))
    elif pc == 0x10f07:
        print('   reg-mismatch jne taken')
    elif pc == 0x10f31:
        print('   nibble-check fail (mode1)')
    elif pc == 0x10f6a:
        print('   op13 fail')
    elif pc == 0x10df5:
        print('   nibble-check mode2 path, passD=0x%02x acc&0xf=0x%x' % (u8(r10), reg('esi') & 0xf))
    else:
        print('>>> VM FAIL'); break
    gdb.execute('continue')
