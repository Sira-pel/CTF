import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))

gdb.Breakpoint('*0x%x' % (B + 0x10dab))   # op10 entry
gdb.Breakpoint('*0x%x' % (B + 0x10e38))   # step: xor esi, [r10-8]
gdb.Breakpoint('*0x%x' % (B + 0x10ee3))   # post-step check
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))   # fail
gdb.execute('run')
n = 0
while n < 200:
    n += 1
    pc = reg('pc') - B
    if pc == 0x10dab:
        print('[op10] mul(imm)=0x%08x tag=%d C=0x%04x' % (u32(reg('rbx')), int(gdb.parse_and_eval('*(unsigned char*)(%d+5)' % reg('rbx'))),
                                                          u16(reg('rbx') + 6)))
    elif pc == 0x10e38:
        r10 = reg('r10')
        print('   step: acc(esi)=0x%08x pass_imm=0x%08x pass_C=0x%04x pass_w4=0x%04x' % (
            reg('esi') & 0xffffffff, u32(r10 - 8), u16(r10 - 2), u16(r10 - 4)))
    elif pc == 0x10ee3:
        print('   -> acc=0x%08x i(r14)=%d' % (reg('esi') & 0xffffffff, reg('r14')))
    else:
        print('>>> FAIL'); break
    gdb.execute('continue')
