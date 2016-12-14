// I wanted to be notified when an address in process changes value.
// Not knowing how to do this I forgot about it for a few months.
// Here I am now though knowing ways to do so.
// Way 1 is by hooking the kernel and dealing with page-faults.
// Way 2 is a hardware-breakpoint API provided by the kernel.
// Way 2 has more details here https://stackoverflow.com/a/19755213
// I did not know about way 2 when I was reading my way through the page-fault
// handling in the kernel and working on my assembly skills for way 1.
// Way 1 is what I'm continuing work on though because I would like to see it
// though.
// There is still lots of cruft in here that I commented but am keeping for
// future reference. That includes dealing with the reading the
// interrupt descriptor table (IDT) for the page-fault trap handler.
// I had the idea that the kernel binary would load to a random location
// on every startup and I'd have to parse the functions to discover the
// randomised location of what I'd want to mess with.
// I was wrong and the kernel loads to a mapping. Now addresses are hardcoded
// for the kernel version.

// The kernel version is the x86-64 4.8.13-1 kernel for Arch Linux.

// An easy fix would be using a kernel I compile with any patches I want to
// do whatever I want. That would solve the problem of the kernel not
// supporting KGDB (kernel GDB). Maybe a custom kernel will be used in the
// future and this can be dropped.

// Status: Doesn't work. Problems changing page protections of the
// kernel binary memory. Haven't looked to far in for a solution yet.
// Also the module only prints a message if a seg-fault is hooked then
// it continues with the original kernel operations.
// No address watching has been implemented yet.

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/fs.h>
#include <linux/proc_fs.h>

#include <linux/atomic.h>

#include <asm/cacheflush.h>
#include <asm/uaccess.h>
#include <asm/traps.h>
//#include <asm/desc.h>
//#include <asm/fixmap.h>

//#include <linux/perf_event.h>
//#include <linux/hw_breakpoint.h>

/*
KERN_EMERG
KERN_ALERT
KERN_CRIT
KERN_ERR
KERN_WARNING
KERN_NOTICE
KERN_INFO
KERN_DEBUG
*/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yachu Pachi");
MODULE_DESCRIPTION("A driver to log reads and writes to addresses in a task.");
MODULE_VERSION("0.1");


#define PROC_ENTRY_NAME "mymaw"


#define REQ_FLAG_UNREGISTER  0x01
#define REQ_FLAG_WATCH_WRITE 0x02
#define REQ_FLAG_WATCH_READ  0x04

#define RESP_FLAG_ERROR       0x01
#define RESP_FLAG_ADDR_CHANGE 0x02
#define RESP_FLAG_PROC_EXIT   0x04
#define RESP_FLAG_READ        0x08
#define RESP_FLAG_WRITE       0x10


struct response_message {
	unsigned long prev_value;
	unsigned long value;
	unsigned char response_code;
};

struct request_message {
	unsigned long addr;
	pid_t pid;
	unsigned char flags;
};



static struct proc_dir_entry *maw_proc_entry = NULL;

//static const gate_desc *my_idt_table = NULL;

//static const void *do_page_fault_ptr = NULL;
//static const void * __bad_area_nosemaphore_ptr = NULL;

int (*set_memory_ro_ptr)(unsigned long, int);
int (*set_memory_rw_ptr)(unsigned long, int);


static ssize_t proc_read(struct file *, char *, size_t, loff_t *);
static ssize_t proc_write(struct file *, const char *, size_t, loff_t *);

static const struct file_operations proc_file_ops = {
	.owner = THIS_MODULE,
	.read = proc_read,
	.write = proc_write,
};

#if 0
static unsigned long __read_gate_func(const gate_desc * g) {
	unsigned long addr =
		  ((unsigned long)g->offset_low)
		| ((unsigned long)g->offset_middle << 16)
		| ((unsigned long)g->offset_high << 32);
	return addr;
}

static const void *read_gate_func(const gate_desc * g) {
	return (const void *)__read_gate_func(g);
}

static const void *HARDCODED_get_do_page_fault(unsigned long idt_dpf) {
	// could do disassemble the idt_dpf function to grab the dynamic address
	// but the address of do_page_fault doesn't change in the loaded kernel
	//return (const void *)0xffffffffffa6e330;
	return (const void *)0xFFFFFFFF810676E0;
}
#endif


//1F5DD350

//REX.W + FF + ?? ?? ?? ?? ??
// 0x48 0xFF +

// CALL rel32 = E8 + ?? ?? ?? ?? --- sign extended to 64-bit

// 8B -- MOVE r16/32/64 r/m16/32/64
// 8B /r MOV r16,r/m16
// 8B /r MOV r32,r/m32

//7...6  5...3  2...0
// Mod    Reg    Reg


// We need to atomically write our "hook" to code memory. If we didn't we
// could encounter a race condition and destroy the OS. To fit a
// CALL instruction to our assembly stub we need at least 5 bytes. So that
// rounds up to 8 bytes and so we now have to replace on an 8 byte boundary for
// the overwrite to be atomic.

// The location we are overwriting is in the start of a MOV instruction.
// The OPcode for the MOV instruction that's before the boundary is 0x8B.


#define _______hook_me_here_address (0xFFFFFFFF81066D30ul)
static unsigned long __hook_me_here_address = _______hook_me_here_address;
static unsigned long * hook_me_here_address =
	((unsigned long *)_______hook_me_here_address);
static unsigned long physss;

static unsigned long original_assembly_bytes;

static unsigned long assembly_hook_bytes_ul;
static unsigned char assembly_hook_bytes_chars[8] = {
	//// 0x8B 0xC0 = MOV eax,eax
	// The 0x8B is right before what we're overwriting.

	0xC0,       // finish the MOV.

	0xE8,       // CALL opcode.
	0, 0, 0, 0, // rel32 for CALL. We fix this to point to our hook stub.

	0x90,       // Fill leftever byte of TEST eax,eax with NOP. We RET to here.
	0x74,       // the start of a JZ opcode. Let's not remove it.
};

// parameter registers
//    rdi rsi rdx rcx r8 r9
// scratch registers
//    rax rdi rsi rdx rcx r8 r9 10 r11
// preserved registers
//    rbx rsp rbp r12 r13 r14 r15

// __bad_area_nosemaphore(regs, error_code, address, vma, si_code)
//                        rdi   rsi         rdx      rcx  r8
// regs is saved in r14
// error_code is saved in rbx
// address is saved in r12
// vma is saved in r10
// si_code is saved in r15d
// tsk is saved in r13

// FFFFFFFF.81066D50   jnz loc_FFFFFFFF.81066E37   ;;; 0F 05 E1 00 00 00

//// This calls force_sig_info_fault
// FFFFFFFF.81066D83   call loc_FFFFFFFF.81066690  ;;; E8 08 F9 FF FF
//    origin = ^ + 5 (to the next instruction)
//       81066D88
//    (int)(08 F9 FF FF) = -1784 ;; the bytes are in little-endian format
//    origin - 1784 = 81066690

//// This moves show_unhandled_signals into eax
// FFFFFFFF.81066D2F   mov  eax,cs:loc_FFFFFFFF.81A28E60 ;;; 8B 05 2B 21 9C 00
//    mov   eax,DWORD PTR [rip+0x9C212B]
//    8B /r    MOV r32,r/m32

int should_we_skip_sigsegv(
	struct pt_regs *regs,
	struct task_struct *tsk,
	struct vm_area_struct *vma,
	unsigned long addr)
{
	if (!tsk || !vma)
		return 0;

	printk(KERN_INFO "MAW: hi there\n");

	return 0;
	//return !!tsk && !!vma && !!addr;
}

// 0 = show_unhandled_signals == 0
// 1 = show_unhandled_signals == 1
// 2 = skip doing the sigsegv
int __our_asm_to_c_interface(
	struct pt_regs *regs,
	struct task_struct *tsk,
	struct vm_area_struct *vma,
	unsigned long addr)
{
	static const int * show_unhandled_signals_ptr =
		(const int *)0xFFFFFFFF81A28E60ul;

	if (should_we_skip_sigsegv(regs, tsk, vma, addr))
		return 2;

	return !!*show_unhandled_signals_ptr;
}

__asm__(
".extern __our_asm_to_c_interface\n"

"we_need_to_send_sigsegv:\n"
	"TEST %eax,%eax\n" // check the show_unhandled_signals value
	"MOVQ $0xFFFFFFFF81066D37,%rax\n"
	"JMP *%rax\n"

"assembly_hook_stub:\n"
	"PUSH %rdi\n"
	"PUSH %rsi\n"
	"PUSH %rdx\n"
	"PUSH %rcx\n"

	"MOV %r14,%rdi\n" // regs
	"MOV %r13,%rsi\n" // tsk
	"MOV %r10,%rdx\n" // vma
	"MOV %r12,%rcx\n" // addr

	"CALL __our_asm_to_c_interface\n"

	"POP %rcx\n"
	"POP %rdx\n"
	"POP %rsi\n"
	"POP %rdi\n"

	"CMP $2,%eax\n" // 2 is returned if we should skip sending sigsegv
	"JNE we_need_to_send_sigsegv\n"
	"MOVQ $0xFFFFFFFF81066D88,%rax\n" // the prologue of __bad_area_nosemaphore
	"JMP *%rax\n"

	//"RET\n"
);
//__attribute__ ((externally_visible))
extern void assembly_hook_stub(void);

long signed_difference(unsigned long a, unsigned long b) {
	unsigned long diff = (a > b) ? (a - b) : (b - a);

	if (diff > S64_MAX)
		return 0;

	return (a > b) ? (long)diff : -(long)diff;
}

static int apply_hook(void) {
	int rel32;
	long diff;
	unsigned long hookie = __hook_me_here_address;
	unsigned long asm_stub_addr = (unsigned long)&assembly_hook_stub;
	physss = virt_to_phys(hook_me_here_address);

	hookie += 6; // CALL rel32 is the offset from the instr after the CALL.
	diff = signed_difference(hookie, asm_stub_addr);

	if (diff == 0 || diff > S32_MAX || diff < S32_MIN)
		return 0;

	rel32 = (int)diff;

	memcpy(&assembly_hook_bytes_chars[2], &rel32, 4);
	memcpy(&assembly_hook_bytes_ul, assembly_hook_bytes_chars, 8);

	original_assembly_bytes = *hook_me_here_address;

	printk(KERN_INFO "MAW: ------------hey--------------\n");
	printk(KERN_INFO "MAW: asm_stub_addr = %lx\n",
		asm_stub_addr);
	printk(KERN_INFO "MAW: __hook_me_here_address = %lx",
		__hook_me_here_address);
	printk(KERN_INFO "MAW: hookie = %lx\n",
		hookie);
	printk(KERN_INFO "MAW: diff = %ld -- %lx\n",
		diff, diff);
	printk(KERN_INFO "MAW: rel32 = %d -- %x\n",
		rel32, rel32);
	printk(KERN_INFO "MAW: original_assembly_bytes = %lx\n",
		original_assembly_bytes);
	printk(KERN_INFO "MAW: assembly_hook_bytes_ul = %lx\n",
		assembly_hook_bytes_ul);
	printk(KERN_INFO "MAW: physss = %lx\n",
		physss);

	set_memory_rw_ptr(physss & PAGE_MASK, 1);
	//set_memory_uc(physss & PAGE_MASK, 1);
	atomic64_set((atomic64_t *)&physss, assembly_hook_bytes_ul);
	set_memory_ro_ptr(physss & PAGE_MASK, 1);

	return 1;

	//kernel_set_to_readonly = 0;
	//set_kernel_text_rw();
	//
}

static void remove_hook(void) {
	set_memory_rw_ptr(physss & PAGE_MASK, 1);
	atomic64_set((atomic64_t *)&physss, original_assembly_bytes);
	set_memory_ro_ptr(physss & PAGE_MASK, 1);
}

static int __init maw_init(void) {
	//int i;
	//unsigned long idt_do_page_fault;
	//struct perf_event_attr attr;
	set_memory_ro_ptr = (void *)kallsyms_lookup_name("set_memory_ro");
	set_memory_rw_ptr = (void *)kallsyms_lookup_name("set_memory_rw");

	(void)maw_proc_entry;

	printk(KERN_INFO "MAW: ----------------------------------------------\n");
	printk(KERN_INFO "MAW: init routine called\n");


	printk(KERN_INFO "MAW: set_memory_ro = %p\n", set_memory_ro_ptr);
	printk(KERN_INFO "MAW: set_memory_rw = %p\n", set_memory_rw_ptr);

	//printk(KERN_INFO "MAW: X86_TRAP_PF = %d\n", X86_TRAP_PF);

	//my_idt_table = (const gate_desc *)fix_to_virt(FIX_RO_IDT);
	//printk(KERN_INFO "MAW: my_idt_table = %p\n", my_idt_table);

	//idt_do_page_fault = __read_gate_func(&my_idt_table[X86_TRAP_PF]);
	//printk(KERN_INFO "MAW: idt_do_page_fault = %lx\n", idt_do_page_fault);

	//do_page_fault_ptr = (const void *)kallsyms_lookup_name("__do_page_fault");
	//do_page_fault_ptr = HARDCODED_get_do_page_fault(idt_do_page_fault);
	//printk(KERN_INFO "MAW: do_page_fault_ptr = %p\n", do_page_fault_ptr);

	//__bad_area_nosemaphore_ptr = (const void *)kallsyms_lookup_name(
	//	"__bad_area_nosemaphore");
	//printk(KERN_INFO "MAW: __bad_area_nosemaphore_ptr = %p\n",
	//	__bad_area_nosemaphore_ptr);

	//printk(KERN_INFO "MAW: assembly_hook_stub = %p\n", assembly_hook_stub);

	//printk(KERN_INFO "MAW: bytes = %lx\n", *hook_me_here_address);

#if 0
	memset(&attr, 0, sizeof(attr));
	hw_breakpoint_init(&attr);
	attr.bp_addr = 0;
	attr.bp_len = HW_BREAKPOINT_LEN_1;
	attr.bp_type = HW_BREAKPOINT_W;
#endif

	printk(KERN_INFO "MAW: maw_init = %p\n", (const void *)maw_init);

	//printk(KERN_INFO "MAW: thing = %lx\n", __hook_me_here_address);
	//printk(KERN_INFO "MAW: thing = %lx\n", __hook_me_here_address & PAGE_MASK);

#if 0
	maw_proc_entry = proc_create(PROC_ENTRY_NAME, (S_IFREG|S_IRUGO), NULL,
		&proc_file_ops);
	if (maw_proc_entry == NULL) {
		remove_proc_entry(PROC_ENTRY_NAME, NULL);

		printk(KERN_ALERT "MAW: failed to create proc entry\n");
		return -ENOMEM;
	}
	printk(KERN_INFO "MAW: successfully created proc entry (%p)\n",
		maw_proc_entry);
#endif

	if (!apply_hook()) {
		printk(KERN_INFO "MAW: failed to apply hook\n");
		return -EACCES;
	}

#if 0
	for (i = 0; i < NR_VECTORS; i++)
	{
		unsigned long addr =
			  ((unsigned long)my_idt_table[i].offset_low)
			| ((unsigned long)my_idt_table[i].offset_middle << 16)
			| ((unsigned long)my_idt_table[i].offset_high << 32);
		printk(KERN_INFO "gate #%03d: func = 0x%lx\n", i, addr);
	}
#endif

	return 0;
}
module_init(maw_init);

static void __exit maw_exit(void) {
	printk(KERN_INFO "MAW: exit routine called\n");

	//remove_proc_entry(PROC_ENTRY_NAME, NULL);

	remove_hook();
	printk(KERN_INFO "MAW: hook removed\n");
}
module_exit(maw_exit);



static ssize_t
proc_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
	int err = 0;

	if (!buffer || !len)
		return -EINVAL;

	//err = _copy_to_user(buffer, do_page_fault_ptr, len);

	if (err == 0) {
		printk(KERN_INFO "MAW: successfully wrote %zu bytes\n", len);
		return len;
	} else {
		printk(KERN_INFO "MAW: failed to write (err = %d)\n", err);
		return -EFAULT;
	}
}

static ssize_t
proc_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
	//struct bad_bad_bad_message bad;

	//if (!buffer || len != sizeof(struct bad_bad_bad_message))
	//	return -EINVAL;

	//memcpy(&bad, buffer, sizeof(bad));

	return len;
}




