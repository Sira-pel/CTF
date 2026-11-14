# Ghidra Jython script: decompile all functions to files
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

outdir = os.environ.get("DECOMP_OUT", "/tmp/ferry_decomp")
if not os.path.isdir(outdir):
    os.makedirs(outdir)

prog = currentProgram
dec = DecompInterface()
dec.openProgram(prog)
mon = ConsoleTaskMonitor()

fm = prog.getFunctionManager()
count = 0
for f in fm.getFunctions(True):
    res = dec.decompileFunction(f, 60, mon)
    if res and res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
    else:
        c = "// decompile failed: %s" % (res.getErrorMessage() if res else "no result")
    name = "%s_%s.c" % (f.getEntryPoint(), f.getName())
    name = name.replace("/", "_").replace(":", "_")
    with open(os.path.join(outdir, name), "w") as fh:
        fh.write("// %s @ %s\n" % (f.getName(), f.getEntryPoint()))
        fh.write(c)
    count += 1

print("DECOMPILED %d functions into %s" % (count, outdir))
