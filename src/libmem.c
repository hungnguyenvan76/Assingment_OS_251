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
int __alloc(struct pcb_t *caller, int vmaid, int rgid, addr_t size, addr_t *alloc_addr)
{
  pthread_mutex_lock(&mmvm_lock); // Lock lại cho an toàn (multithread)
  struct vm_rg_struct rgnode;

  // BƯỚC 1: Thử tìm trong kho hàng cũ (Tái sử dụng)
  if (get_free_vmrg_area(caller, vmaid, size, &rgnode) == 0)
  {
    // Tìm thấy! Cập nhật bảng ký hiệu biến (Symbol Table)
    caller->krnl->mm->symrgtbl[rgid].rg_start = rgnode.rg_start;
    caller->krnl->mm->symrgtbl[rgid].rg_end = rgnode.rg_end;
    *alloc_addr = rgnode.rg_start;

    pthread_mutex_unlock(&mmvm_lock);
    return 0;
  }

  // BƯỚC 2: Hết hàng cũ -> Phải nới rộng bộ nhớ (Heap Expansion)
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->krnl->mm, vmaid);
  
  // Tính toán kích thước cần nới (Phải làm tròn theo Page Size - Alignment)
  // Ví dụ cần 10 byte, nhưng mỗi lần xin phải xin chẵn 256 byte (1 page)
  int inc_sz = PAGING_PAGE_ALIGNSZ(size); 
  
  int old_sbrk = cur_vma->sbrk; // Lưu lại mốc biên giới cũ (đây sẽ là địa chỉ bắt đầu của user)

  // Gọi System Call nhờ Kernel nới đất
  struct sc_regs regs;
  regs.a1 = SYSMEM_INC_OP; // Opcode nới bộ nhớ
  regs.a2 = vmaid;
  regs.a3 = inc_sz;        // Kích thước muốn nới
  syscall(caller->krnl, caller->pid, 17, &regs); // Gọi sys_memmap (ID 17)

  // BƯỚC 3: Cập nhật bảng ký hiệu cho vùng nhớ mới toanh này
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
int __free(struct pcb_t *caller, int vmaid, int rgid)
{
  pthread_mutex_lock(&mmvm_lock);

  // Validate đầu vào
  if (rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ) {
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }

  // 1. Lấy thông tin vùng nhớ từ ID
  struct vm_rg_struct *rgnode = get_symrg_byid(caller->krnl->mm, rgid);
  
  // Kiểm tra xem biến này có được cấp phát chưa
  if (rgnode->rg_start == 0 && rgnode->rg_end == 0) {
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }

  // 2. Tạo node mới để lưu vào kho "Đất bỏ hoang"
  struct vm_rg_struct *freerg_node = malloc(sizeof(struct vm_rg_struct));
  freerg_node->rg_start = rgnode->rg_start;
  freerg_node->rg_end = rgnode->rg_end;
  
  // 3. Chèn vào đầu danh sách (LIFO behavior for free list)
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->krnl->mm, vmaid);
  freerg_node->rg_next = cur_vma->vm_freerg_list;
  cur_vma->vm_freerg_list = freerg_node;

  // 4. Xóa thông tin sở hữu trong bảng ký hiệu (User không còn sở hữu nữa)
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
int pg_getpage(struct mm_struct *mm, int pgn, int *fpn, struct pcb_t *caller)
{
  uint32_t pte = pte_get_entry(caller, pgn);

  // Trường hợp 1: Trang đã có trong RAM (Present)
  if (PAGING_PAGE_PRESENT(pte))
  {
      *fpn = PAGING_FPN(pte);
      return 0;
  }

  // Trường hợp 2: Page Fault (Trang không có trong RAM) -> Phải Swap
  // Chúng ta sẽ lấy một khung trang (frame) từ một trang khác đang ở trong RAM (victim)
  
  addr_t vicpgn; // Page number của nạn nhân
  int vicfpn;    // Frame number của nạn nhân (sẽ lấy cái này cho trang mới)
  uint32_t vicpte;

  // 1. Tìm nạn nhân để đá ra (Dùng thuật toán FIFO đã viết ở trên)
  if (find_victim_page(caller->krnl->mm, &vicpgn) < 0)
  {
      return -1; // Không tìm được nạn nhân (Lỗi nghiêm trọng)
  }

  // 2. Lấy thông tin frame của nạn nhân
  vicpte = pte_get_entry(caller, vicpgn);
  vicfpn = PAGING_FPN(vicpte);

  // 3. Lấy một slot trống trong ổ đĩa Swap để chứa nạn nhân
  // Lưu ý: Đề bài yêu cầu lấy từ active_mswp
  int swpfpn; 
  if (MEMPHY_get_freefp(caller->krnl->active_mswp, &swpfpn) < 0) {
      // Nếu ổ Swap đầy -> Không thể swap out -> Lỗi
      return -1;
  }

  // 4. THỰC HIỆN SWAP (Giao tiếp với Hardware qua Syscall)
  // Logic: Copy dữ liệu từ RAM[vicfpn] sang SWAP[swpfpn]
  // VÀ: Copy dữ liệu từ SWAP[của trang pgn] sang RAM[vicfpn] (Nếu trang pgn đã từng bị swap ra)
  
  // Gọi syscall SWAP. Tham số:
  // a2: Frame trong RAM (vicfpn)
  // a3: Frame trong Swap (swpfpn)
  // Lưu ý: syscall này thực hiện __mm_swap_page trong kernel
  struct sc_regs regs;
  regs.a1 = SYSMEM_SWP_OP;
  regs.a2 = vicfpn;
  regs.a3 = swpfpn; 
  syscall(caller->krnl, caller->pid, 17, &regs);


  // 5. Cập nhật Page Table của NẠN NHÂN (Giờ nó đã ra đảo/swap ở)
  // Đánh dấu: SWAPPED = 1, PRESENT = 0
  // Lưu vị trí trên ổ đĩa: SWAP TYPE và SWAP OFFSET
  pte_set_swap(caller, vicpgn, 0, swpfpn); 


  // 6. Cập nhật Page Table của TRANG CẦN DÙNG (Giờ nó đã vào đất liền/RAM)
  // Đánh dấu: PRESENT = 1, SWAPPED = 0
  // Gán cho nó cái frame của nạn nhân vừa để lại (vicfpn)
  pte_set_fpn(caller, pgn, vicfpn);

  // 7. Thêm trang mới vào danh sách FIFO để quản lý cho lần sau
  enlist_pgn_node(&caller->krnl->mm->fifo_pgn, pgn);

  // 8. Trả về kết quả Frame Number
  *fpn = vicfpn;

  return 0;
}

/*pg_getval - read value at given offset
 *@mm: memory region
 *@addr: virtual address to acess
 *@value: value
 *
 */
int pg_getval(struct mm_struct *mm, int addr, BYTE *data, struct pcb_t *caller)
{
  int pgn = PAGING_PGN(addr);
//  int off = PAGING_OFFST(addr);
  int fpn;

  if (pg_getpage(mm, pgn, &fpn, caller) != 0)
    return -1; /* invalid page access */

//  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;

  /* TODO 
   *  MEMPHY_read(caller->krnl->mram, phyaddr, data);
   *  MEMPHY READ 
   *  SYSCALL 17 sys_memmap with SYSMEM_IO_READ
   */

  return 0;
}

/*pg_setval - write value to given offset
 *@mm: memory region
 *@addr: virtual address to acess
 *@value: value
 *
 */
int pg_setval(struct mm_struct *mm, int addr, BYTE value, struct pcb_t *caller)
{
  int pgn = PAGING_PGN(addr);
//  int off = PAGING_OFFST(addr);
  int fpn;

  /* Get the page to MEMRAM, swap from MEMSWAP if needed */
  if (pg_getpage(mm, pgn, &fpn, caller) != 0)
    return -1; /* invalid page access */


  /* TODO 
   *  MEMPHY_write(caller->krnl->mram, phyaddr, value);
   *  MEMPHY WRITE with SYSMEM_IO_WRITE 
   * SYSCALL 17 sys_memmap
   */

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

  struct vm_area_struct *cur_vma = get_vma_by_num(caller->krnl->mm, vmaid);
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
int find_victim_page(struct mm_struct *mm, addr_t *retpgn)
{
  struct pgn_t *pg = mm->fifo_pgn;

  // Case 0: Danh sách rỗng
  if (!pg)
    return -1;

  // Case 1: Danh sách chỉ có 1 phần tử
  if (pg->pg_next == NULL) {
      *retpgn = pg->pgn;
      mm->fifo_pgn = NULL; // Cập nhật lại head
      free(pg);
      return 0;
  }

  // Case 2: Danh sách có >= 2 phần tử -> Tìm đuôi (Tail)
  struct pgn_t *prev = NULL;
  while (pg->pg_next)
  {
    prev = pg;
    pg = pg->pg_next;
  }
  
  *retpgn = pg->pgn;
  prev->pg_next = NULL; // Cắt đuôi
  free(pg);

  return 0;
}

/*get_free_vmrg_area - get a free vm region
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@size: allocated size
 *
 */
int get_free_vmrg_area(struct pcb_t *caller, int vmaid, int size, struct vm_rg_struct *newrg)
{
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->krnl->mm, vmaid);
  struct vm_rg_struct *rgit = cur_vma->vm_freerg_list; // Con trỏ chạy
  struct vm_rg_struct *prev = NULL; // Con trỏ lưu node trước đó (để nối lại chuỗi khi xóa)

  if (rgit == NULL) return -1; // Hết đất

  // Duyệt danh sách
  while (rgit != NULL)
  {
    if (rgit->rg_start + size <= rgit->rg_end) // Tìm thấy vùng đủ chỗ!
    { 
      // 1. Ghi nhận kết quả trả về cho user
      newrg->rg_start = rgit->rg_start;
      newrg->rg_end = rgit->rg_start + size;

      // 2. Xử lý phần dư thừa trong danh sách
      if (rgit->rg_start + size < rgit->rg_end)
      {
        // Case B: Còn dư -> Chỉ cần dịch start lên, node vẫn giữ đó
        rgit->rg_start += size;
      }
      else
      { 
        // Case A: Vừa khít -> Phải xóa node này khỏi danh sách
        if (prev != NULL) {
            prev->rg_next = rgit->rg_next; // Nối node trước với node sau
        } else {
            cur_vma->vm_freerg_list = rgit->rg_next; // Nếu xóa node đầu thì cập nhật head
        }
        free(rgit); // Giải phóng cái vỏ struct (node quản lý)
      }
      return 0; // Success
    }
    
    // Chưa tìm thấy, đi tiếp
    prev = rgit;
    rgit = rgit->rg_next;
  }

  return -1; // Duyệt hết mà không có
}

// #endif
