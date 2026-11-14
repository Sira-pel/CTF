import gdb, re, sys

gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('set confirm off')
gdb.execute('starti')

out = gdb.execute('info files', to_string=True)
m = re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', out)
entry = int(m.group(1), 16)
B = entry - 0xf020
print('BASE = 0x%x' % B)

PASS_HEX = sys.argv[1] if len(sys.argv) > 1 else None

def b(off):
    return int(gdb.parse_and_eval('(char*)0x%x' % (B + off)))

def stop(off):
    gdb.Breakpoint('*0x%x' % (B + off))

def u8(a): return int(gdb.parse_and_eval('*(unsigned char*)%d' % a))
def u16(a): return int(gdb.parse_and_eval('*(unsigned short*)%d' % a))
def u32(a): return int(gdb.parse_and_eval('*(unsigned int*)%d' % a))
def u64(a): return int(gdb.parse_and_eval('*(unsigned long*)%d' % a))
def sp(): return int(gdb.parse_and_eval('$sp'))

# trace VM dispatch: rbx = current entry pointer
stop(0x10a96)
gdb.execute('run')
for _ in range(400):
    pc = None
    try:
        r12 = int(gdb.parse_and_eval('$r12'))
        rbx_ = int(gdb.parse_and_eval('$rbx'))
        # entry at rbx: 12 bytes: B(4) op(1) tag(1) C(2) D(1) pad(3)
        Bv = u32(rbx_)
        op = u8(rbx_+4)
        tag = u8(rbx_+5)
        C = u16(rbx_+6)
        D = u8(rbx_+8)
        S = sp()
        i = u64(S)          # [rsp] = index
        acc = u64(S+8)      # r15
        print('i=%d op=%d tag=%d C=%d B=0x%x D=%d' % (i, op, tag, C, Bv, D))
    except Exception as e:
        print('err', e)
        break
    gdb.execute('continue')
