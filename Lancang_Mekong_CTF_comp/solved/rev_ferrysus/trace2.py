import gdb, re, sys

gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('starti')

out = gdb.execute('info proc mappings', to_string=True)
base = None
for line in out.splitlines():
    if 'ferry-inspect' in line:
        m = re.match(r'\s*(0x[0-9a-f]+)', line)
        if m:
            base = int(m.group(1), 16)
            break
if base is None:
    print('NO BASE'); sys.exit(1)
print('BASE=0x%x' % base)
B = base

def bp(off, name):
    gdb.execute('break *0x%x' % (B + off))

bp(0x11b7d, 'key')
gdb.execute('run')
