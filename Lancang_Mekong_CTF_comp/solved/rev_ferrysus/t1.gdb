set pagination off
set confirm off
set disable-randomization on
starti
set $fbase = $pc - 0xf020
printf "BASE=0x%lx\n", $fbase

# checker entry args
break *($fbase+0x101b0)
commands
silent
printf "== checker entry: rdi=%p rsi=%ld rdx=%p rcx=%ld r8=%ld\n", $rdi, $rsi, $rdx, $rcx, $r8
continue
end

# after pass section decode (before VM setup)
break *($fbase+0x108aa)
commands
silent
printf "== after decode: count(r11)=%ld instrptr=%p\n", $r11, *(void**)($rsp+0x1b8)
x/60xb *(void**)($rsp+0x1b8)
continue
end

# VM dispatch
break *($fbase+0x10aa5)
commands
silent
printf "VM pc=%p item: ", $rbx
x/12xb $rbx
printf "   regs: "
x/8gx ($rsp+0xf0)
continue
end

# success / fail
break *($fbase+0x11a8a)
commands
silent
printf "   -> OK\n"
continue
end
break *($fbase+0x11f6a)
commands
silent
printf "   -> FAIL\n"
continue
end
break *($fbase+0x11fbb)
commands
silent
printf "== end of VM (rbx==0 or loop end)\n"
continue
end
break *($fbase+0x11af5)
commands
silent
printf "== VM loop done, keyvalid=%d stage=%d key=0x%x\n", *(unsigned char*)($rsp+0xc0), *(unsigned char*)($rsp+0xc8), *(unsigned int*)($rsp+0xe4)
continue
end
break *($fbase+0x11b7d)
commands
silent
printf "== decrypt stage: key=0x%x\n", $eax
continue
end
break *($fbase+0x11fd4)
commands
silent
printf "== final: r8=%ld passlen(rbp)=%ld\n", $r8, $rbp
continue
end
run
