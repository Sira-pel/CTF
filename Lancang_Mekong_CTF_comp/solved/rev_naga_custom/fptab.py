import sys, random, pickle
from multiprocessing import Pool
sys.path.insert(0, '/home/sira/Documents/CTF/Lancang_Mekong_CTF_comp/solved/rev_naga_custom')
from model import *

def mk(seed):
    r = random.Random(seed)
    out = []
    for p in range(6):
        es = r.sample(range(65536), 12)
        for i in range(12):
            out.append((r.randrange(12), r.randrange(1, 1024), r.randrange(1, 256), r.randrange(1, 366), es[i]))
    return out

DECLS = {"A": mk(101), "B": mk(202), "C": mk(303)}

def work(k):
    return [fingerprint(simulate(k, d)[1]) for d in (DECLS["A"], DECLS["B"], DECLS["C"])]

if __name__ == "__main__":
    with Pool(8) as p:
        res = p.map(work, range(65536), chunksize=512)
    pickle.dump(res, open('/tmp/claude-1000/-home-sira--claude-spares-spare-GKF30R/82842250-d20e-492b-9228-fe3a89eef61c/scratchpad/fptab.pkl', 'wb'))
    print("done", len(res))
