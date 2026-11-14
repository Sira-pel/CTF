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
    except Exception:
        return b'<err>'

hooks = []
for off in [0xfe09, 0xfe37, 0xff18, 0x101b0, 0x10212, 0x11fbb, 0x11b7d, 0x11fd4]:
    gdb.Breakpoint('*0x%x' % (B + off))

gdb.execute('run')
n = 0
while n < 40:
    n += 1
    pc = reg('pc') - B
    try:
        if pc == 0xfe09:
            r11 = reg('r11')
            print('[gate-arg] vec=0x%x' % r11)
            for k in range(5):
                b0 = r11 + 0x18 * k
                print('   el%d: +0=0x%x +8=0x%x +16=0x%x' % (k, u64(b0), u64(b0+8), u64(b0+16)))
        elif pc == 0xfe37:
            r11 = reg('r11')
            print('[pass-arg] ptr=0x%x len=%d' % (u64(r11+0x38), u64(r11+0x40)))
            print('   str=', memstr(u64(r11+0x38), min(u64(r11+0x40), 40)))
        elif pc == 0xff18:
            print('[call-checker] rdi=0x%x rsi=%d rdx=0x%x rcx=%d r8=0x%x' % (reg('rdi'), reg('rsi'), reg('rdx'), reg('rcx'), reg('r8')))
            print('   pass=', memstr(reg('rdx'), min(reg('rcx'), 48)).hex(' '))
        elif pc == 0x101b0:
            print('[checker] rdi=0x%x rsi=%d rdx=0x%x rcx=%d r8=0x%x' % (reg('rdi'), reg('rsi'), reg('rdx'), reg('rcx'), reg('r8')))
        elif pc == 0x10212:
            print('   [p4] passlen=%d pass=%s' % (reg('rcx'), memstr(reg('r13'), min(reg('rcx'), 48)).hex(' ')))
        elif pc == 0x11fbb:
            print('   [vm-end]')
        elif pc == 0x11b7d:
            print('   [stage-key] eax=0x%x' % u32(reg('rsp') + 0))
        elif pc == 0x11fd4:
            print('   [final] r8(passlen after?) =%d rbp=%d' % (reg('r8'), reg('rbp')))
    except Exception as e:
        print('read err', e)
    gdb.execute('continue')
