import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))

for off in (0x10af2, 0x10e24, 0x10e38, 0x10e70, 0x10e7c, 0x10e90, 0x10e9a, 0x10eb5, 0x10ec7, 0x10ee3, 0x10f07):
    gdb.Breakpoint('*0x%x' % (B + off))
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))
gdb.execute('run')
n = 0
while n < 80:
    n += 1
    pc = reg('pc') - B
    r10 = reg('r10'); rbx = reg('rbx')
    if pc == 0x10af2:
        print('[op10 start] total bytes(rax-24)=%d' % ((reg('rax') - 24)))
    elif pc == 0x10e24:
        print('[step i=%d] acc=0x%08x w4=0x%04x' % (reg('r14'), reg('esi') & 0xffffffff, u32(r10 - 8) & 0xffff))
    elif pc == 0x10e38:
        print('   xor->0x%08x C(ptr2)=0x%04x' % ((reg('esi') ^ u32(r10 - 8)) & 0xffffffff, u16(r10 - 2)))
    elif pc == 0x10e70:
        print('   cl=%d' % ((reg('rsi') & 0xff)))
    elif pc in (0x10e90, 0x10e9a, 0x10eb5, 0x10ec7):
        print('   branch case @%x' % pc)
    elif pc == 0x10ee3:
        print('   -> acc=0x%08x' % (reg('esi') & 0xffffffff))
    elif pc == 0x10f07:
        print('   >>> reg mismatch'); break
    else:
        print('>>> fail'); break
    gdb.execute('continue')
