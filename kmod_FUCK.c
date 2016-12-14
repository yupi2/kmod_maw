// Purpose: random code that I used to inspect the other module or fix anything
// while the other module is loaded or hung.

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/fs.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yachu Pachi");
MODULE_DESCRIPTION("A driver that fixes problems with the other driver.");
MODULE_VERSION("0.1");


#define PROC_ENTRY_NAME "mymaw"

/*
[15871.472623] MAW: set_memory_ro = ffffffff8106b270
[15871.472624] MAW: set_memory_rw = ffffffff8106b2b0
[15871.473051] MAW: do_page_fault_ptr = ffffffff810671d0
[15871.473474] MAW: __bad_area_nosemaphore_ptr = ffffffff81066cb0
[15871.473475] MAW: assembly_hook_stub = ffffffffa113a00b
[15871.473476] MAW: bytes = 74c085009c212b05
[15871.473477] MAW: maw_init = ffffffffa0005000


[18199.251023] FUCK: bss_sec[0] = ffffffff8106b2b0
[18199.251024] FUCK: bss_sec[1] = ffffffff8106b270
[18199.251026] FUCK: bss_sec[2] = 7490dff2cd2be8c0
*/


//static struct proc_dir_entry *maw_proc_entry = NULL;

void find_maw_proc_entry(void) {
	//unsigned long dpf_ptr = 0xffffffff810671d0ul;
	//int i;
	//unsigned long **bss_sec = (unsigned long **)0xffffffffa113c000;//0xffffffffa113c380;

	//for (i = 0; i < 4; i++)
	//	printk(KERN_INFO "FUCK: data_sec[%d] = %p\n", i, bss_sec[i]);

	//printk(KERN_INFO "FUCK: data_sec[0] = %lx\n",
	//	*((unsigned long *)0xffffffffa113c000));

	//printk(KERN_INFO "FUCK: bss_sec[0] = %p\n", bss_sec[0]);
	//printk(KERN_INFO "FUCK: bss_sec[1] = %p\n", bss_sec[1]);
	//printk(KERN_INFO "FUCK: bss_sec[2] = %p\n", bss_sec[2]);

	//if (res)
	//	maw_proc_entry = (const void *)((const char *)res - 8);
}

static int __init FUCK_YOU(void) {
	printk(KERN_INFO "FUCK: ----------------------------------------------\n");
	//remove_proc_entry(PROC_ENTRY_NAME, NULL);
	//printk(KERN_INFO "FUCK: REMOVED proc entry\n");

	//ind_maw_proc_entry();
	//maw_proc_entry = ((void *)0xffff880400cec480);
	//printk(KERN_INFO "FUCK: maw_proc_entry = %p\n", maw_proc_entry);
	//remove_proc_entry(PROC_ENTRY_NAME, maw_proc_entry);

	printk(KERN_INFO "FUCK: *hook_me_here_address = %lx\n",
		*((unsigned long *)0xffffffff81066d30ul));

	return 0;
}

static void __exit AND_A_FUCKYOU(void) {
	printk(KERN_INFO "FUCK: exit routine called\n");

	//remove_proc_entry(PROC_ENTRY_NAME, NULL);
}

module_init(FUCK_YOU);
module_exit(AND_A_FUCKYOU);




