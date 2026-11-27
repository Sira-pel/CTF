# Kernel Monarch (HTB, rev, Hard)

**Flag:** `HTB{sysc4ll_h00k_34sy_byp4ss3d!}`

## Summary
`malware.ko` is an ftrace-hook rootkit (kallsyms_lookup_name via kprobe + `fh_install_hooks`, 6 hooks).
`init_module` does `printk(KERN_INFO "%s\n", flag)` — in the shipped .ko the string is a decoy
(`HTB{f4k3_fl4g_f0r_r3v3rs1ng_0nly}`); the real flag sits in the remote VM's kernel log.

## Hooks
- `__x64/ia32_sys_syslog`, `do_syslog` → return -1 (dmesg fails/empty).
- `__x64_sys_read`: if `file->f_path.dentry->d_name` is `kmsg`/`kallsyms`/`enabled_functions`/`touched_functions`,
  drop lines containing `taint` or `malware`.
- `__x64/ia32_sys_write`: writes to `ftrace_enabled`/`tracing_on` are swallowed (fake success).
- `hide()`: list_del from module list + kobject_del (gone from /proc/modules).

## Bypass
Remote = QEMU busybox root shell (nc). Filter keys on the dentry name only, so:
```
mknod /tmp/zz c 1 11
dd if=/tmp/zz iflag=nonblock bs=8192 count=3000 | grep HTB
```
(readv/pread/sendfile also unhooked.) Wait ~10s after connecting; early input gets eaten during boot.

## Lesson
Name-based filtering in a read hook → alias the device under another name. Check the remote for the real flag when the .ko shows a "fake" one.
