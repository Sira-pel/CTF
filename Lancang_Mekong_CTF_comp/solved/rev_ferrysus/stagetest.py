#!/usr/bin/env python3
import sys, struct
sys.path.insert(0, '.')
from kvm import parse_route, toprog, decrypt, section, build, run
from solve2 import solve1

recs = parse_route()
s1 = solve1(toprog(recs[0]))

def slots1():
    return [bytes([s1['w4'][i] & 0xff, (s1['w4'][i] >> 8) & 0xff]) + struct.pack('<H', s1['Cv'][i]) +
            struct.pack('<I', s1['p0'][i]) + bytes([0, 0xa5 ^ (s1['w4'][i] & 0xff) ^ ((s1['w4'][i] >> 8) & 0xff)])
            for i in range(s1['n'])]

for stage in (0, 1, 2, 3):
    d = build(section(stage, slots1(), sum(s1['Cv'].values()) & 0xffff, 0x7c))
    open(f'/tmp/st{stage}.bin', 'wb').write(d)
    r = run(d)
    print('stage=%d len=%d rc=%d %r' % (stage, len(d), r.returncode, r.stdout.strip()))
