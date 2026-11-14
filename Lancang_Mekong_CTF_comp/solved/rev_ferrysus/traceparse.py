import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x101d8))   # after FUN_10f200 header parse
gdb.Breakpoint('*0x%x' % (B + 0x1022f))   # header reject path
gdb.Breakpoint('*0x%x' % (B + 0x10212))   # magic check
gdb.Breakpoint('*0x%x' % (B + 0x10706))   # after offset target validated
gdb.Breakpoint('*0x%x' % (B + 0x108aa))   # after section parsed
gdb.execute('run')
for _ in range(30):
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x101d8:
        print('[hdr] pass=%s' % mem(reg('rsi'), min(reg('rdx'), 24)).hex())
    elif pc == 0x10212:
        print('[magic] len=%d pass=%s' % (reg('rcx'), mem(reg('rdx'), min(reg('rcx'), 24)).hex()))
    elif pc == 0x1022f:
        print('[reject-header]')
    elif pc == 0x10706:
        rax = reg('rax'); rdx = reg('rdx'); rdi = reg('rdi')
        print('[offset ok] target_off=0x%x sec_end=0x%x' % (rax, rdi))
    elif pc == 0x108aa:
        print('[sec parsed] count(r11)=%d  entries=0x%x' % (reg('r11'), u64(S + 0x18)))
        e = u64(S + 0x18)
        if e: print('   first 36:', mem(e, 36).hex(' '))
    gdb.execute('continue')
