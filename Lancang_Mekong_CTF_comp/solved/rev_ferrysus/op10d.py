import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))

for off in (0x10de4, 0x10e38, 0x10ee3, 0x10f07, 0x11f6a):
    gdb.Breakpoint('*0x%x' % (B + off))
gdb.execute('run')
n = 0
while n < 60:
    n += 1
    pc = reg('pc') - B
    r10 = reg('r10')
    if pc == 0x10de4:
        print('[op10] n=%d mul=0x%08x modebyte=%d' % (reg('r9') if False else reg('rax'), u32(reg('rbx')), u8(reg('rbx') + 5)))
    elif pc == 0x10e38:
        print('  i=%d acc=0x%08x | item p0=0x%08x w4=0x%04x C=0x%04x' % (
            reg('r14'), reg('esi') & 0xffffffff, u32(r10 - 8), u16(r10 - 4), u16(r10 - 2)))
    elif pc == 0x10ee3:
        print('     -> acc=0x%08x  regwant=%d/0x%08x' % (reg('esi') & 0xffffffff,
              u32(reg('rsp') + reg('r14') * 8 + 0x1b0), u32(reg('rsp') + reg('r14') * 8 + 0x1b4)))
    elif pc == 0x10f07:
        print('  >>> REG MISMATCH at i=%d' % reg('r14')); break
    else:
        print('>>> FAIL'); break
    gdb.execute('continue')
