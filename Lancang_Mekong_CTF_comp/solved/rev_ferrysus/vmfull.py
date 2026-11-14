import gdb, re, sys, json

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
    except Exception: return b''

gdb.Breakpoint('*0x%x' % (B + 0x10aa5))   # after rbx=r12 (cur), r12=next
gdb.Breakpoint('*0x%x' % (B + 0x11b58))   # stage loop next stage
gdb.Breakpoint('*0x%x' % (B + 0x11fd4))   # final compare
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))   # vm fail
gdb.execute('run')

trace = []
n = 0
while n < 4000:
    n += 1
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x10aa5:
        rbx = reg('rbx')
        d = mem(rbx, 8)
        if len(d) < 8: break
        imm = int.from_bytes(d[0:4], 'little'); op = d[4]; tag = d[5]; C = int.from_bytes(d[6:8], 'little')
        idx = u64(S)
        acc = reg('rsi')
        entp = u64(S + 0x18)
        cnt = u64(S)
        trace.append(dict(i=idx, op=op, tag=tag, C=C, imm=imm, acc=acc & 0xffffffff))
        print('i=%-3d op=%-2d tag=%-3d C=%-5d imm=0x%08x acc=0x%08x entp=0x%x stage=%d' % (
            idx, op, tag, C, imm, acc & 0xffffffff, entp, u64(S + 0x48) & 0xff))
    elif pc == 0x11b58:
        S = reg('sp')
        print('== next stage: id=%d off=%d flag=%d key=0x%x' % (reg('rcx') & 0xff, u64(S + 0x28), u64(S + 0xc0) & 0xff, u64(S + 0xe4) & 0xffffffff))
        print('   entries ptr=0x%x count=%d' % (u64(S + 0x18), u64(S)))
        ep = u64(S + 0x18)
        if ep:
            dd = mem(ep, 12 * 8)
            for k in range(min(8, len(dd) // 12)):
                e = dd[12*k:12*k+12]
                print('     ent%d: %s' % (k, e.hex(' ')))
    elif pc == 0x11fd4:
        print('== FINAL r8=%d rbp=%d' % (reg('r8'), reg('rbp')))
    else:
        print('== VM FAIL')
        break
    gdb.execute('continue')
