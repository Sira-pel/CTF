import gdb, re, sys, struct

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

gdb.Breakpoint('*0x%x' % (B + 0x10a9f))   # rbx = cur instr ptr
gdb.Breakpoint('*0x%x' % (B + 0x11af5))   # VM done
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))   # VM fail
gdb.Breakpoint('*0x%x' % (B + 0x11b7d))   # stage key
gdb.Breakpoint('*0x%x' % (B + 0x11fd4))   # final
gdb.execute('run')

n = 0
while n < 3000:
    n += 1
    pc = reg('pc') - B
    if pc == 0x10a9f:
        r12 = reg('r12')
        S = sp()
        ent = r12
        imm = u32(ent)
        op = u8(ent + 4); tag = u8(ent + 5); C = u16(ent + 6); D = u8(ent + 8)
        print('VM op=%-2d imm=0x%08x tag=%d C=0x%04x D=%d  i=%d acc=0x%x cnt=%d' % (
            op, imm, tag, C, D, u64(S), reg('rsi'), u64(S + 0xd0) if False else 0))
    elif pc == 0x11af5:
        S = sp()
        print('== VM DONE  flag928=%d stage=%d key=0x%x' % (u8(S + 0xc0), u8(S + 0xc8), u32(S + 0xe4)))
    elif pc == 0x11f6a:
        print('== VM FAIL')
    elif pc == 0x11b7d:
        print('== stage key 0x%x' % reg('eax'))
    elif pc == 0x11fd4:
        print('== FINAL r8=%d rbp=%d' % (reg('r8'), reg('rbp')))
    gdb.execute('continue')
