import gdb, re, sys

gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
print('BASE = 0x%x' % B)

def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def reg(n): return int(gdb.parse_and_eval('$' + n))
def sp(): return reg('sp')
def memstr(a, n):
    try:
        return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception as e:
        return b'<err>'

for off in [0xf801, 0xf93a, 0xff18, 0x101b0, 0x10212]:
    gdb.Breakpoint('*0x%x' % (B + off))

gdb.execute('run')
for step in range(6):
    pc = reg('pc') - B
    print('--- hit off 0x%x  rsp=0x%x' % (pc, sp()))
    if pc == 0xf801:
        rcx = reg('rcx')
        print('vec base rcx=0x%x' % rcx)
        for k in range(4):
            base = rcx + k * 0x18
            print('  arg[%d] ptr=0x%x cap=%d len=%d' % (k, u64(base), u64(base+8), u64(base+16)))
        print('  argc=%d' % reg('rbp'))
    elif pc == 0xf93a:
        rdi = reg('rdi')
        print('  hexdecode result disc=%d' % u32(rdi))
        for k in range(0, 0x40, 8):
            print('   [%02x]=0x%x' % (k, u64(rdi + k)))
    elif pc == 0xff18:
        print('  checker args: rdi=0x%x rsi=%d rdx=0x%x rcx=%d r8=0x%x' % (reg('rdi'), reg('rsi'), reg('rdx'), reg('rcx'), reg('r8')))
        print('   route rec0 bytes:', memstr(reg('rdi'), 32).hex(' '))
        print('   pass bytes:', memstr(reg('rsi'), min(reg('rdx'), 64)).hex(' '))
    elif pc == 0x101b0:
        print('  checker: rdi=0x%x rsi=%d rdx=0x%x rcx=%d r8=0x%x' % (reg('rdi'), reg('rsi'), reg('rdx'), reg('rcx'), reg('r8')))
        print('   pass:', memstr(reg('rsi'), min(reg('rdx'), 64)).hex(' '))
    elif pc == 0x10212:
        print('  param4(rcx)=%d  r13=0x%x' % (reg('rcx'), reg('r13')))
        print('   pass:', memstr(reg('r13'), min(reg('rcx'), 64)).hex(' '))
    gdb.execute('continue')
