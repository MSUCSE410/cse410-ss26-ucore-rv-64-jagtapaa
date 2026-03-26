#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"
#define MAX_SYSCALL_NUM 500

uint64 sys_getpid();
uint64 sys_mmap(uint64 start, uint64 len, int prot);
uint64 sys_munmap(uint64 start, uint64 len);

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}
// asks kernel what time it is
uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	struct proc *p = curr_proc();
	uint64 pa = useraddr(p->pagetable, (uint64)val);
	if (pa == 0)
		return -1;

	TimeVal *tv = (TimeVal *)pa;
	uint64 cycle = get_cycle();
	tv->sec = cycle / CPU_FREQ;
	tv->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
/*
* LAB1: you may need to define sys_task_info here
*/
uint64 sys_task_info(TaskInfo *ti)
{
	struct proc *p = curr_proc();
	uint64 pa = useraddr(p->pagetable, (uint64)ti);
	if (pa == 0)
		return -1;

	TaskInfo *info = (TaskInfo *)pa;

	info->status = Running;

	for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
		info->syscall_times[i] = p->syscall_times[i];
	}

	uint64 now = get_cycle();
	info->time = (now - p->start_cycle) * 1000 / CPU_FREQ;

	return 0;
}

extern char trap_page[];

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

// allocates memory in virtual address space
// start: the user virtual address where mapping begins
// len: how many bytes the user wants mapped
// prot: permissions memory should have
uint64 sys_mmap(uint64 start, uint64 len, int prot)
{
	if (start % PGSIZE != 0)
		return -1;
	if (len == 0)
		return -1;
	if (start >= MAXVA)
		return -1;
	if (start + len < start)
		return -1;
	if (start + len > MAXVA)
		return -1;
	if ((prot & ~0x7) != 0)
		return -1;

	int perm = 0;
	if (prot & 0x1)
		perm |= PTE_R; // read
	if (prot & 0x2)
		perm |= PTE_W; // write
	if (prot & 0x4)
		perm |= PTE_X; // execute

	if (perm == 0)
		return -1;

	struct proc *p = curr_proc();
	uint64 npages = (len + PGSIZE - 1) / PGSIZE;

	for (uint64 i = 0; i < npages; i++) {
		uint64 va = start + i * PGSIZE;

		if (walkaddr(p->pagetable, va) != 0)
			return -1;

		void *pa = kalloc();
		if (pa == 0)
			return -1;

		memset(pa, 0, PGSIZE);

		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa,
			     perm | PTE_U) < 0) {
			kfree(pa);
			return -1;
		}
	}

	// converts byte length into number of pages
	uint64 end_page = (start + len + PGSIZE - 1) / PGSIZE;
	if (end_page > p->max_page)
		p->max_page = end_page;

	return 0;
}

// unallocates memory 
// start: where mapped region begins
// len: how much to remove
uint64 sys_munmap(uint64 start, uint64 len)
{
	if (start % PGSIZE != 0)
		return -1;
	if (len == 0)
		return -1;
	if (start >= MAXVA)
		return -1;
	if (start + len < start)
		return -1;
	if (start + len > MAXVA)
		return -1;

	struct proc *p = curr_proc();
	uint64 npages = (len + PGSIZE - 1) / PGSIZE;

	for (uint64 i = 0; i < npages; i++) {
		uint64 va = start + i * PGSIZE;
		// checks whether page is mapped so that it prevents unmapped memory that doesn't exist
		if (walkaddr(p->pagetable, va) == 0)
			return -1;
	}
	
	// removes page table entries for that address range
	uvmunmap(p->pagetable, start, npages, 1);
	return 0;
}

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		curr_proc()->syscall_times[id]++;
	}
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	case SYS_task_info:
		ret = sys_task_info((TaskInfo *)args[0]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;

	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
