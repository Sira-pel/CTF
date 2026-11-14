import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def uq(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x1104b))   # op16
gdb.execute('run')
for _ in range(16):
    S = int(gdb.parse_and_eval('$sp'))
    rbx = int(gdb.parse_and_eval('$rbx'))
    tag = int(gdb.parse_and_eval('*(unsigned char*)%d' % (rbx + 5)))
    imm = int(gdb.parse_and_eval('*(unsigned int*)%d' % rbx))
    print('op16 tag=%d imm=0x%08x stage=%d  regtab dump:' % (tag, imm, uq(S + 0xc8) & 0xff))
    print('   ', u(S + 0x1b0, 48).hex(' '))
    gdb.execute('continue')
