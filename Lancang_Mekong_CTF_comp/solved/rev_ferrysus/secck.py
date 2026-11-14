import gdb, re, sys

gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('starti')
out = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out).group(1), 16)
B = entry - 0xf020
def reg(n): return int(gdb.parse_and_eval('$' + n))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))
def mem(a, n):
    try: return gdb.selected_inferior().read_memory(a, n).tobytes()
    except Exception: return b'<err>'

gdb.Breakpoint('*0x%x' % (B + 0x10538))
gdb.execute('run')
S = reg('sp')
print('secloop: r9=%d rbp(passlen)=%d r13(passptr)=0x%x r14=%d rdi=%d' % (
    reg('r9'), reg('rbp'), reg('r13'), reg('r14'), reg('rdi')))
print('pass bytes:', mem(reg('r13'), reg('rbp')).hex(' '))
# decode: pass[0:4]=magic, then the FS section
p = mem(reg('r13'), reg('rbp'))
print('header:', p[:8].hex(' '))
print('sec1  :', p[4:20].hex(' '))
