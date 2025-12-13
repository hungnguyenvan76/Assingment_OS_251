/*
 * Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* LamiaAtrium release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

// #ifdef MM_PAGING
/*
 * System Library
 * Memory Module Library libmem.c 
 */

#include "string.h"
#include "../include/mm.h"
#include "../include/mm64.h"
#include "../include/syscall.h"
#include "../include/libmem.h"
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "common.h"

static pthread_mutex_t mmvm_lock = PTHREAD_MUTEX_INITIALIZER;

/*enlist_vm_freerg_list - add new rg to freerg_list
 *@mm: memory region
 *@rg_elmt: new region
 *
 */
int enlist_vm_freerg_list(struct mm_struct *mm, struct vm_rg_struct *rg_elmt)
{
  struct vm_rg_struct *rg_node = mm->mmap->vm_freerg_list;

  if (rg_elmt->rg_start >= rg_elmt->rg_end)
    return -1;

  if (rg_node != NULL)
    rg_elmt->rg_next = rg_node;

  /* Enlist the new region */
  mm->mmap->vm_freerg_list = rg_elmt;

  return 0;
}

/*get_symrg_byid - get mem region by region ID
 *@mm: memory region
 *@rgid: region ID act as symbol index of variable
 *
 */
struct vm_rg_struct *get_symrg_byid(struct mm_struct *mm, int rgid)
{
  if (rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ)
    return NULL;

  return &mm->symrgtbl[rgid];
}

/*__alloc - allocate a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size
 *@alloc_addr: address of allocated memory region
 *
 */
int __alloc(struct pcb_t *caller, int vmaid, int rgid, addr_t size, addr_t *alloc_addr) {
  pthread_mutex_lock(&mmvm_lock); //lock 
  struct vm_rg_struct rgnode;

  //Tai su dung
  if (get_free_vmrg_area(caller, vmaid, size, &rgnode) == 0) {
    caller->krnl->mm->symrgtbl[rgid].rg_start = rgnode.rg_start;
    caller->krnl->mm->symrgtbl[rgid].rg_end = rgnode.rg_end;
    *alloc_addr = rgnode.rg_start;

    pthread_mutex_unlock(&mmvm_lock);
    return 0;
  }

  //Neu khong co -> mo rong bo nho
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->krnl->mm, vmaid);
  
  //Tinh toan kich thuoc can mo rong
  int inc_sz = PAGING_PAGE_ALIGNSZ(size); 
  
  int old_sbrk = cur_vma->sbrk; 

  //goi system call -> kernal mo rong
  struct sc_regs regs;
  regs.a1 = SYSMEM_INC_OP; 
  regs.a2 = vmaid;
  regs.a3 = inc_sz;        
  syscall(caller->krnl, caller->pid, 17, &regs);

  //cap nhat bang ky hieu cho vung nho moi
  caller->krnl->mm->symrgtbl[rgid].rg_start = old_sbrk;
  caller->krnl->mm->symrgtbl[rgid].rg_end = old_sbrk + size;

  *alloc_addr = old_sbrk;

  pthread_mutex_unlock(&mmvm_lock);
  return 0;
}       

/*__free - remove a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size
 *
 */
int __free(struct pcb_t *caller, int vmaid, int rgid) {
  pthread_mutex_lock(&mmvm_lock); //lock

  //kiem tra dau vao
  if (rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ) {
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }

  //lay thong tin vung nho tu ID
  struct vm_rg_struct *rgnode = get_symrg_byid(caller->krnl->mm, rgid);
  
  //kiem tra xem da cap phat chua
  if (rgnode->rg_start == 0 && rgnode->rg_end == 0) {
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }

  //tao node moi de luu
  struct vm_rg_struct *freerg_node = malloc(sizeof(struct vm_rg_struct));
  freerg_node->rg_start = rgnode->rg_start;
  freerg_node->rg_end = rgnode->rg_end;
  
  //chen vao dau danh sach
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->krnl->mm, vmaid);
  freerg_node->rg_next = cur_vma->vm_freerg_list;
  cur_vma->vm_freerg_list = freerg_node;

  //xoa thong tin so huu
  rgnode->rg_start = 0;
  rgnode->rg_end = 0;
  rgnode->rg_next = NULL;

  pthread_mutex_unlock(&mmvm_lock);
  return 0;
}

/*liballoc - PAGING-based allocate a region memory
 *@proc:  Process executing the instruction
 *@size: allocated size
 *@reg_index: memory region ID (used to identify variable in symbole table)
 */
int liballoc(struct pcb_t *proc, addr_t size, uint32_t reg_index)
{
  addr_t  addr;

  int val = __alloc(proc, 0, reg_index, size, &addr);
  if (val == -1)
  {
    return -1;
  }
#ifdef IODUMP
  /* TODO dump IO content (if needed) */
#ifdef PAGETBL_DUMP
  print_pgtbl(proc, 0, -1); // print max TBL
#endif
#endif

  /* By default using vmaid = 0 */
  return val;
}

/*libfree - PAGING-based free a region memory
 *@proc: Process executing the instruction
 *@size: allocated size
 *@reg_index: memory region ID (used to identify variable in symbole table)
 */

int libfree(struct pcb_t *proc, uint32_t reg_index)
{
  int val = __free(proc, 0, reg_index);
  if (val == -1)
  {
    return -1;
  }
printf("%s:%d\n",__func__,__LINE__);
#ifdef IODUMP
  /* TODO dump IO content (if needed) */
#ifdef PAGETBL_DUMP
  print_pgtbl(proc, 0, -1); // print max TBL
#endif
#endif
  return 0;//val;
}

/*pg_getpage - get the page in ram
 *@mm: memory region
 *@pagenum: PGN
 *@framenum: return FPN
 *@caller: caller
 *
 */
int pg_getpage(struct mm_struct *mm, int pgn, int *fpn, struct pcb_t *caller) {
  uint32_t pte = pte_get_entry(caller, pgn);

  //trang da co trong RAM
  if (PAGING_PAGE_PRESENT(pte)) {
      *fpn = PAGING_FPN(pte);
      return 0;
  }

  //page fault -> xu ly Swap
  addr_t vicpgn;
  int vicfpn; 
  uint32_t vicpte;

  //chon trang victim de swap out
  if (find_victim_page(caller->krnl->mm, &vicpgn) < 0)
      return -1;

  //lay frame cua nan nhan
  vicpte = pte_get_entry(caller, vicpgn);
  vicfpn = PAGING_FPN(vicpte);

  //tim slot trong ben Swap
  // --- DA SUA: int -> addr_t ---
  addr_t swpfpn; 
  if (MEMPHY_get_freefp(caller->krnl->active_mswp, &swpfpn) < 0)
      return -1;

  //goi Syscall SWAP: Copy RAM -> Swap va Swap -> RAM
  struct sc_regs regs;
  regs.a1 = SYSMEM_SWP_OP;
  regs.a2 = vicfpn;
  regs.a3 = swpfpn; 
  syscall(caller->krnl, caller->pid, 17, &regs);

  //cap nhat PTE nan nhan: danh dau Swapped
  pte_set_swap(caller, vicpgn, 0, swpfpn); 

  //cap nhat PTE trang moi: danh dau Present, lay frame cua victim
  pte_set_fpn(caller, pgn, vicfpn);

  //them vao danh sach FIFO quan ly
  enlist_pgn_node(&caller->krnl->mm->fifo_pgn, pgn);

  *fpn = vicfpn;

  return 0;
}
/*pg_getval - read value at given offset
 *@mm: memory region
 *@addr: virtual address to acess
 *@value: value
 *
 */
int pg_getval(struct mm_struct *mm, int addr, BYTE *data, struct pcb_t *caller) {
  //giai ma dia chi
  int pgn = PAGING_PGN(addr);
  int off = PAGING_OFFST(addr);
  int fpn;

  //kiem tra xem page co trong ram khong
  if (pg_getpage(mm, pgn, &fpn, caller) != 0)
    return -1; 

  //tinh dia chi tuyet doi (vat ly)
  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off; 

  //syscall -> kernal doc ram vat ly
  struct sc_regs regs;
  regs.a1 = SYSMEM_IO_READ; //syscall doc
  regs.a2 = phyaddr;        //dia chi
  regs.a3 = 0;              //placeholder

  syscall(caller->krnl, caller->pid, 17, &regs);

  *data = (BYTE)regs.a3; //lay gia tri

  return 0;
}

/*pg_setval - write value to given offset
 *@mm: memory region
 *@addr: virtual address to acess
 *@value: value
 *
 */
int pg_setval(struct mm_struct *mm, int addr, BYTE value, struct pcb_t *caller) {
  int pgn = PAGING_PGN(addr);
  int off = PAGING_OFFST(addr);
  int fpn;

  //kiem tra xem page co trong ram khong
  if (pg_getpage(mm, pgn, &fpn, caller) != 0)
    return -1; 

  //tinh dia chi tuyet doi (vat ly)
  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;

  //syscall -> kernal ghi vao ram vat ly
  struct sc_regs regs;
  regs.a1 = SYSMEM_IO_WRITE;
  regs.a2 = phyaddr;
  regs.a3 = (uint32_t)value;  //gia tri can ghi

  syscall(caller->krnl, caller->pid, 17, &regs);

  return 0;
}

/*__read - read value in region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@offset: offset to acess in memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size
 *
 */
int __read(struct pcb_t *caller, int vmaid, int rgid, addr_t offset, BYTE *data)
{
  struct vm_rg_struct *currg = get_symrg_byid(caller->krnl->mm, rgid);
  pthread_mutex_lock(&mmvm_lock);
//  struct vm_area_struct *cur_vma = get_vma_by_num(caller->krnl->mm, vmaid);

  /* TODO Invalid memory identify */
  if (currg == NULL) {
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }

  //struct vm_area_struct *cur_vma = get_vma_by_num(caller->krnl->mm, vmaid);
  int ret = pg_getval(caller->krnl->mm, currg->rg_start + offset, data, caller);

  pthread_mutex_unlock(&mmvm_lock);
  return ret;
}

/*libread - PAGING-based read a region memory */
int libread(
    struct pcb_t *proc, // Process executing the instruction
    uint32_t source,    // Index of source register
    addr_t offset,    // Source address = [source] + [offset]
    uint32_t* destination)
{
  BYTE data;
  int val = __read(proc, 0, source, offset, &data);

  *destination = data;
#ifdef IODUMP
  /* TODO dump IO content (if needed) */
#ifdef PAGETBL_DUMP
  print_pgtbl(proc, 0, -1); // print max TBL
#endif
#endif

  return val;
}

/*__write - write a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@offset: offset to acess in memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size
 *
 */
int __write(struct pcb_t *caller, int vmaid, int rgid, addr_t offset, BYTE value)
{
  pthread_mutex_lock(&mmvm_lock);
  struct vm_rg_struct *currg = get_symrg_byid(caller->krnl->mm, rgid);

  struct vm_area_struct *cur_vma = get_vma_by_num(caller->krnl->mm, vmaid);

  if (currg == NULL || cur_vma == NULL) /* Invalid memory identify */
  {
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }

  pg_setval(caller->krnl->mm, currg->rg_start + offset, value, caller);

  pthread_mutex_unlock(&mmvm_lock);
  return 0;
}

/*libwrite - PAGING-based write a region memory */
int libwrite(
    struct pcb_t *proc,   // Process executing the instruction
    BYTE data,            // Data to be wrttien into memory
    uint32_t destination, // Index of destination register
    addr_t offset)
{
  int val = __write(proc, 0, destination, offset, data);
  if (val == -1)
  {
    return -1;
  }
#ifdef IODUMP
#ifdef PAGETBL_DUMP
  print_pgtbl(proc, 0, -1); // print max TBL
#endif
  MEMPHY_dump(proc->krnl->mram);
#endif

  return val;
}

/*free_pcb_memphy - collect all memphy of pcb
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@incpgnum: number of page
 */
int free_pcb_memph(struct pcb_t *caller)
{
  pthread_mutex_lock(&mmvm_lock);
  int pagenum, fpn;
  uint32_t pte;

  for (pagenum = 0; pagenum < PAGING_MAX_PGN; pagenum++)
  {
    pte = caller->krnl->mm->pgd[pagenum];

    if (PAGING_PAGE_PRESENT(pte))
    {
      fpn = PAGING_FPN(pte);
      MEMPHY_put_freefp(caller->krnl->mram, fpn);
    }
    else
    {
      fpn = PAGING_SWP(pte);
      MEMPHY_put_freefp(caller->krnl->active_mswp, fpn);
    }
  }

  pthread_mutex_unlock(&mmvm_lock);
  return 0;
}


/*find_victim_page - find victim page
 *@caller: caller
 *@pgn: return page number
 *
 */
int find_victim_page(struct mm_struct *mm, addr_t *retpgn) {
  struct pgn_t *pg = mm->fifo_pgn;  //lay dau danh sach

  //danh sach rong
  if (!pg)
    return -1;

  //danh sach chi co 1 phan tu
  if (pg->pg_next == NULL) {
      *retpgn = pg->pgn;
      mm->fifo_pgn = NULL;
      free(pg);
      return 0;
  }

  //Danh sach co > 1 phan tu
  struct pgn_t *prev = NULL;
  while (pg->pg_next) { //duyet den tail
    prev = pg;
    pg = pg->pg_next;
  }
  
  *retpgn = pg->pgn;  //node cuoi cung, da ra khoi list
  prev->pg_next = NULL; 
  free(pg);

  return 0;
}

/*get_free_vmrg_area - get a free vm region
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@size: allocated size
 *
 */

int get_free_vmrg_area(struct pcb_t *caller, int vmaid, int size, struct vm_rg_struct *newrg) {
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->krnl->mm, vmaid);
  struct vm_rg_struct *rgit = cur_vma->vm_freerg_list;    //con tro de duyet
  struct vm_rg_struct *prev = NULL;                       //con tro luu node truoc do

  //khong con vung de cap phat
  if (rgit == NULL) {
    return -1; 
  } 

  //duyet qua danh sach
  while (rgit != NULL) {
    if (rgit->rg_start + size <= rgit->rg_end) {  //tim thay vung du cho de cap phat
      newrg->rg_start = rgit->rg_start;
      newrg->rg_end = rgit->rg_start + size;

      if (rgit->rg_start + size < rgit->rg_end) {  //xu ly phan du thua
        //con du -> dich start len (khong giai phong node)
        rgit->rg_start += size;
      } else { 
        //vua khit -> giai phong node khoi danh sach
        if (prev != NULL) {
            prev->rg_next = rgit->rg_next; //noi node truoc voi sau
        } else {
            cur_vma->vm_freerg_list = rgit->rg_next; //neu xoa node dau -> update head
        }

        free(rgit);
      }

      return 0; //bao thanh cong
    }
    
    //chua tim thay, di tiep
    prev = rgit;
    rgit = rgit->rg_next;
  }

  return -1; //duyet het nhung khong con cho trong
}

// #endif
