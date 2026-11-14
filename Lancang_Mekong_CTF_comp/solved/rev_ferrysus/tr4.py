import gdb, re, sys

gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020

def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def reg(n): return int(gdb.parse_and_eval('$' + n))
def sp(): return reg('sp')
def memstr(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

for off in [0x1022f, 0x102a2, 0x10333, 0x10538, 0x10561, 0x11ed5, 0x11f00, 0x11f6a, 0x11af5, 0x1028e]:
    gdb.Breakpoint('*0x%x' % (B + off))
gdb.execute('run')

n = 0
while n < 60:
    n += 1
    pc = reg('pc') - B
    S = sp()
    if pc == 0x1022f:
        print('[1022f rejected-header] passlen=%d' % reg('rbp'))
    elif pc == 0x102a2:
        print('[102a2 pass-ok] numrecs=%d' % u64(S + 0x140))
    elif pc == 0x10333:
        print('[10333 iter] uVar20(%d) uVar43(%d) off=%d' % (u64(S + 0x118) if False else 0, 0, u64(S + 0x9c0) if False else 0))
    elif pc == 0x10538:
        print('[10538 secloop] r9(off)=%d rbp(len)=%d' % (reg('r9'), reg('rbp')))
    elif pc == 0x10561:
        print('   magic check at r9=%d: bytes=%s' % (reg('r9'), memstr(reg('r13') + reg('r9'), 8).hex(' ')))
    elif pc == 0x11ed5:
        print('   [parse error -> 11ed5]')
    elif pc == 0x11f00:
        print('   [fail 11f00]')
    elif pc == 0x11f6a:
        print('   [VMfail]')
    elif pc == 0x11af5:
        print('   [VMdone]')
    elif pc == 0x1028e:
        print('   [return %d]' % reg('ebx'))
    gdb.execute('continue')
