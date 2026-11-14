set pagination off
set confirm off
set disable-randomization on
starti
set $b = $pc - 0xf020
printf "BASE = %p\n", $b
# checker entry
break *($b+0x101b0)
# after memcpy of route record 0 into fresh buffer
break *($b+0x10303)
# FS magic check in section parse loop
break *($b+0x10561)
# decryption done
break *($b+0x11d40)
# VM dispatch
break *($b+0x10a96)
run
