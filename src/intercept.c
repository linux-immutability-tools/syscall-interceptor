// intercept.c
// author: axtlos / axtloss <axtlos@disroot.org>
// SPDX-LICENSE: GPL-2.0-ONLY

#include <asm/unistd_64.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/namei.h>
#include <linux/utsname.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <asm/special_insns.h>

MODULE_LICENSE ("GPL");

unsigned long *sys_call_table;
int flag = 0;
unsigned long umount_orig;
unsigned long fsmount_orig;
static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

asmlinkage long block_syscall(const char *pathname)
{
    pr_info("blocked\n");
        return -1;
}

static int __init intercept_init (void)
{

	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	pr_info("%lu\n", kallsyms_lookup_name("sys_call_table"));
	sys_call_table = kallsyms_lookup_name("sys_call_table");
	pr_info("%lu\n", sys_call_table[__NR_move_mount]);

	long (*funcPointer)(const char *) = block_syscall;
	pr_info("%lu\n", (long unsigned int)funcPointer);

	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
    asm volatile("mov %0,%%cr0" : "+r"(cr0));
    pr_info("save\n");
    umount_orig = sys_call_table[__NR_move_mount];
    fsmount_orig = sys_call_table[__NR_fsmount];
    pr_info("%lu\n", (long unsigned int)umount_orig);
    pr_info("%lu\n", (long unsigned int)fsmount_orig);
    pr_info("%lu\n", (long unsigned int)sys_call_table);
    pr_info("hook\n");
 	sys_call_table[__NR_move_mount] = (unsigned long)hacked_sys_unlink;
	sys_call_table[__NR_fsmount] = (unsigned long)hacked_sys_unlink;

	cr0 = (unsigned long)read_cr0;
	set_bit(16, &cr0);

    pr_info("test\n");
    return 0;
}

static void intercept_exit (void) {
    pr_info("tes\n");
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    asm volatile("mov %0,%%cr0" : "+r"(cr0));
    pr_info("reset");
    sys_call_table[__NR_move_mount] = umount_orig;
    sys_call_table[__NR_fsmount] = fsmount_orig;
    pr_info("readonly\n");
    cr0 = read_cr0();
    set_bit(16, &cr0);
}

module_init(intercept_init);
module_exit(intercept_exit);
