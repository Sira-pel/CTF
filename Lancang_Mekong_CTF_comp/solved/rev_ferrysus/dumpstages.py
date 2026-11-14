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

gdb.Breakpoint('*0x%x' % (B + 0x11d40))     # stage decrypted: r14=buf r15=len
gdb.Breakpoint('*0x%x' % (B + 0x11fd4))     # final
gdb.Breakpoint('*0x%x' % (B + 0x11f6a))     # VM fail
gdb.execute('run')
n = 0
while n < 30:
    n += 1
    pc = reg('pc') - B
    if pc == 0x11d40:
        buf, ln = reg('r14'), reg('r15')
        d = mem(buf, ln)
        print('=== stage %d decrypted len=%d' % (n, ln))
        print(d.hex())
        for k in range(0, len(d), 8):
            w = d[k:k+8]
            if len(w) < 8: break
            imm = int.from_bytes(w[0:4], 'little'); op = w[4]; tag = w[5]; C = int.from_bytes(w[6:8], 'little')
            print('   w%-2d imm=0x%08x op=%-2d tag=%-3d C=0x%04x  %s' % (k//8, imm, op, tag, C, w.hex(' ')))
    else:
        print('hit', hex(pc))
        break
    gdb.execute('continue')
