import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10ac4))     # op1 handler
gdb.Breakpoint('*0x%x' % (B + 0x10a10))
gdb.execute('run')
hit_setup = False
while True:
    pc = reg('pc') - B
    S = reg('sp')
    if pc == 0x10a10:
        hit_setup = True
        print('[setup] progcount=%d H(section byte6)=0x%02x' % (reg('rbx'), u64(S + 0x37) if False else 0))
        # find pass section H
        print('   [rsp+0x28]=0x%x' % u64(S + 0x28))
        print('   [rsp+0x37]=0x%02x' % int(gdb.parse_and_eval('*(unsigned char*)%d' % (S + 0x37))))
    else:
        rbx = reg('rbx')
        print('[op1] item.byte0=0x%02x  [rsp+0x37]=0x%02x  prog=0x%x' % (
            int(gdb.parse_and_eval('*(unsigned char*)%d' % rbx)),
            int(gdb.parse_and_eval('*(unsigned char*)%d' % (S + 0x37))), rbx))
        break
    gdb.execute('continue')
