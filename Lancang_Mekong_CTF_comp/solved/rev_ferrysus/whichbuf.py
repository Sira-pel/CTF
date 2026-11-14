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

gdb.Breakpoint('*0x%x' % (B + 0x10a10))
gdb.execute('run')
S = reg('sp')
print('count(rbx)=%d' % reg('rbx'))
print('[rsp+0x90]=0x%x  [rsp+0x98]=0x%x [rsp+0xa0]=0x%x' % (u64(S+0x90), u64(S+0x98), u64(S+0xa0)))
print('[rsp+0x18]=0x%x [rsp+0x28]=0x%x [rsp+0x50]=0x%x' % (u64(S+0x18), u64(S+0x28), u64(S+0x50)))
print('[rsp+0x70]=0x%x [rsp+0x78]=0x%x [rsp+0x88]=0x%x' % (u64(S+0x70), u64(S+0x78), u64(S+0x88)))
for name, addr, n in [('0x90buf', u64(S+0x90), 64), ('0x18buf', u64(S+0x18), 64), ('0x28buf', u64(S+0x28), 64), ('0x50buf', u64(S+0x50), 64)]:
    print('%s @0x%x: %s' % (name, addr, mem(addr, n).hex(' ') if addr else '-'))
print('--- stack locals 0x30..0xa8:')
print(mem(S+0x30, 0x78).hex(' '))
