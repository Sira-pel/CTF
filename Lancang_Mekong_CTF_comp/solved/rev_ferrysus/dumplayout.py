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
    except Exception: return b''

gdb.Breakpoint('*0x%x' % (B + 0x10a10))
gdb.execute('run')
S = reg('sp')
print('rbx(count)=%d  [rsp+0x90]=0x%x' % (reg('rbx'), u64(S + 0x90)))
print('[rsp+0x18]=0x%x  [rsp+0xd0]=0x%x' % (u64(S + 0x18), u64(S + 0xd0)))
p = u64(S + 0x90)
print('dump 12*count  :', mem(p, 12 * reg('rbx')).hex(' '))
print('dump 8*count   :', mem(p, 8 * reg('rbx')).hex(' '))
print('dump 10*count  :', mem(p, 10 * reg('rbx')).hex(' '))
print('decoded @0x18  :', mem(u64(S+0x18), 60).hex(' '))
