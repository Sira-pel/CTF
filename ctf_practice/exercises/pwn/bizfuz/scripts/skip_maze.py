import gdb

# Addresses of "number handler" calls in main BEFORE our target (skip them entirely)
MAIN_SKIP_CALLS = [
0x814ce14,0x814ce19,0x814ce30,0x814ce59,0x814ce5e,0x814ce87,0x814ce9e,0x814cea3,
0x814ceba,0x814cebf,0x814ced6,0x814ceff,0x814cf04,0x814cf2d,0x814cf44,0x814cf49,
0x814cf60,0x814cf65,0x814cf7c,0x814cfa5,0x814cfaa,0x814cfd3,0x814cfea,0x814cfef,
0x814d006,0x814d00b,0x814d022,0x814d04b,0x814d050,0x814d079,0x814d090,0x814d095,
0x814d0ac,0x814d0b1,0x814d0c8,
]

# "Noise" subtree calls inside our 5 target functions that we don't need (skip them)
NOISE_SKIP_CALLS = [0x813d6bf, 0x8144bcf, 0x81321a6, 0x81321c1]

QUIZ_ENTRY = 0x08049261

# scores to force, in order, for the 9 quiz calls we care about
SCORE_QUEUE = [0,0, 0,0, 0,0,0, 5, 1]
score_idx = [0]

class SkipCallBP(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__(f"*0x{addr:x}", internal=False)
        self.silent = True
    def stop(self):
        pc = int(gdb.parse_and_eval("$pc"))
        newpc = pc + 5  # length of e8 call rel32
        gdb.execute(f"set $pc = 0x{newpc:x}")
        return False  # don't actually stop

class QuizBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__(f"*0x{QUIZ_ENTRY:x}", internal=False)
        self.silent = True
    def stop(self):
        # return address is at [esp]
        esp = int(gdb.parse_and_eval("$esp"))
        inferior = gdb.selected_inferior()
        ret_bytes = inferior.read_memory(esp, 4)
        ret_addr = int.from_bytes(bytes(ret_bytes), 'little')
        if score_idx[0] < len(SCORE_QUEUE):
            val = SCORE_QUEUE[score_idx[0]]
        else:
            val = 0
        print(f"[quiz call #{score_idx[0]+1}] forcing score={val}, returning to 0x{ret_addr:x}")
        score_idx[0]+=1
        gdb.execute(f"set $eax = {val}")
        gdb.execute(f"set $pc = 0x{ret_addr:x}")
        # also need to pop the return address off stack (ret would do esp+=4)
        gdb.execute(f"set $esp = {esp+4}")
        if score_idx[0] >= len(SCORE_QUEUE):
            print("=== All critical quiz calls handled, deleting this breakpoint, continuing normally ===")
            return True  # stop so we can detach further handling / let real input flow
        return False

for a in MAIN_SKIP_CALLS:
    SkipCallBP(a)
for a in NOISE_SKIP_CALLS:
    SkipCallBP(a)
QuizBP()

print("=== breakpoints installed, continuing ===")
gdb.execute("continue")
