/*
 * Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* LamiaAtrium release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

/*
 * PAGING based Memory Management
 * Memory management unit mm/mm64.c
 */

#include "mm64.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include <pthread.h> 

#if defined(MM64)

/*
 * init_pte - Initialize PTE entry
 */
int init_pte(addr_t *pte,
             int pre,    // present
             addr_t fpn,    // FPN
             int drt,    // dirty
             int swp,    // swap
             int swptyp, // swap type
             addr_t swpoff) // swap offset
{
  if (pre != 0) {
    if (swp == 0) { // Non swap ~ page online
      if (fpn == 0)
        return -1;  // Invalid setting

      /* Valid setting with FPN */
      SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
      CLRBIT(*pte, PAGING_PTE_SWAPPED_MASK);
      CLRBIT(*pte, PAGING_PTE_DIRTY_MASK);

      SETVAL(*pte, fpn, PAGING_PTE_FPN_MASK, PAGING_PTE_FPN_LOBIT);
    }
    else
    { // page swapped
      SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
      SETBIT(*pte, PAGING_PTE_SWAPPED_MASK);
      CLRBIT(*pte, PAGING_PTE_DIRTY_MASK);

      SETVAL(*pte, swptyp, PAGING_PTE_SWPTYP_MASK, PAGING_PTE_SWPTYP_LOBIT);
      SETVAL(*pte, swpoff, PAGING_PTE_SWPOFF_MASK, PAGING_PTE_SWPOFF_LOBIT);
    }
  }

  return 0;
}

/*
 * get_pd_from_address - Parse address to 5 page directory level
 */
int get_pd_from_address(addr_t addr, addr_t* pgd, addr_t* p4d, addr_t* pud, addr_t* pmd, addr_t* pt)
{
  /* Extract page directories using bit masking and shifting */
  *pgd = (addr & PAGING64_ADDR_PGD_MASK) >> PAGING64_ADDR_PGD_LOBIT;
  *p4d = (addr & PAGING64_ADDR_P4D_MASK) >> PAGING64_ADDR_P4D_LOBIT;
  *pud = (addr & PAGING64_ADDR_PUD_MASK) >> PAGING64_ADDR_PUD_LOBIT;
  *pmd = (addr & PAGING64_ADDR_PMD_MASK) >> PAGING64_ADDR_PMD_LOBIT;
  *pt  = (addr & PAGING64_ADDR_PT_MASK)  >> PAGING64_ADDR_PT_LOBIT;

  return 0;
}

/*
 * get_pd_from_pagenum - Parse page number to 5 page directory level
 */
int get_pd_from_pagenum(addr_t pgn, addr_t* pgd, addr_t* p4d, addr_t* pud, addr_t* pmd, addr_t* pt)
{
  /* Shift the page number to get virtual address then perform mapping */
  return get_pd_from_address(pgn << PAGING64_ADDR_PT_SHIFT, pgd, p4d, pud, pmd, pt);
}

/*
 * pte_set_swap - Set PTE entry for swapped page
 */
int pte_set_swap(struct pcb_t *caller, addr_t pgn, int swptyp, addr_t swpoff)
{
  struct krnl_t *krnl = caller->krnl;
  struct mm_struct *mm = krnl->mm;
  addr_t *pte;
  addr_t pgd_idx = 0, p4d_idx = 0, pud_idx = 0, pmd_idx = 0, pt_idx = 0;
  int ret = 0;

  // LOCK
  pthread_mutex_lock(&mm->mm_lock);

#ifdef MM64 
  /* Get indices from page number */
  get_pd_from_pagenum(pgn, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);
  
  /* Traverse multi-level page table to get PTE */
  // Level 5: PGD
  if (mm->pgd == NULL) {
    mm->pgd = malloc(512 * sizeof(addr_t));
    if (mm->pgd == NULL) { ret = -1; goto done; }
    memset(mm->pgd, 0, 512 * sizeof(addr_t));
  }
  
  // Level 4: P4D
  if (mm->pgd[pgd_idx] == 0) {
    addr_t *new_p4d = malloc(512 * sizeof(addr_t));
    if (new_p4d == NULL) { ret = -1; goto done; }
    memset(new_p4d, 0, 512 * sizeof(addr_t));
    mm->pgd[pgd_idx] = (addr_t)new_p4d;
  }
  addr_t *p4d_table = (addr_t *)mm->pgd[pgd_idx];
  
  // Level 3: PUD
  if (p4d_table[p4d_idx] == 0) {
    addr_t *new_pud = malloc(512 * sizeof(addr_t));
    if (new_pud == NULL) { ret = -1; goto done; }
    memset(new_pud, 0, 512 * sizeof(addr_t));
    p4d_table[p4d_idx] = (addr_t)new_pud;
  }
  addr_t *pud_table = (addr_t *)p4d_table[p4d_idx];
  
  // Level 2: PMD
  if (pud_table[pud_idx] == 0) {
    addr_t *new_pmd = malloc(512 * sizeof(addr_t));
    if (new_pmd == NULL) { ret = -1; goto done; }
    memset(new_pmd, 0, 512 * sizeof(addr_t));
    pud_table[pud_idx] = (addr_t)new_pmd;
  }
  addr_t *pmd_table = (addr_t *)pud_table[pud_idx];
  
  // Level 1: PT
  if (pmd_table[pmd_idx] == 0) {
    addr_t *new_pt = malloc(512 * sizeof(addr_t));
    if (new_pt == NULL) { ret = -1; goto done; }
    memset(new_pt, 0, 512 * sizeof(addr_t));
    pmd_table[pmd_idx] = (addr_t)new_pt;
  }
  addr_t *pt_table = (addr_t *)pmd_table[pmd_idx];
  
  pte = &pt_table[pt_idx];
#else
  pte = &mm->pgd[pgn];
#endif
  
  SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
  SETBIT(*pte, PAGING_PTE_SWAPPED_MASK);

  SETVAL(*pte, swptyp, PAGING_PTE_SWPTYP_MASK, PAGING_PTE_SWPTYP_LOBIT);
  SETVAL(*pte, swpoff, PAGING_PTE_SWPOFF_MASK, PAGING_PTE_SWPOFF_LOBIT);

done:
  // UNLOCK
  pthread_mutex_unlock(&mm->mm_lock);
  return ret;
}

/*
 * pte_set_fpn - Set PTE entry for on-line page
 */
int pte_set_fpn(struct pcb_t *caller, addr_t pgn, addr_t fpn)
{
  struct krnl_t *krnl = caller->krnl;
  struct mm_struct *mm = krnl->mm;
  addr_t *pte;
  addr_t pgd_idx = 0, p4d_idx = 0, pud_idx = 0, pmd_idx = 0, pt_idx = 0;
  int ret = 0;
  pthread_mutex_lock(&mm->mm_lock);
  
#ifdef MM64 
  get_pd_from_pagenum(pgn, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);
  
  if (mm->pgd == NULL) {
    mm->pgd = malloc(512 * sizeof(addr_t));
    if (mm->pgd == NULL) { ret = -1; goto done; }
    memset(mm->pgd, 0, 512 * sizeof(addr_t));
  }
  
  if (mm->pgd[pgd_idx] == 0) {
    addr_t *new_p4d = malloc(512 * sizeof(addr_t));
    if (new_p4d == NULL) { ret = -1; goto done; }
    memset(new_p4d, 0, 512 * sizeof(addr_t));
    mm->pgd[pgd_idx] = (addr_t)new_p4d;
  }
  addr_t *p4d_table = (addr_t *)mm->pgd[pgd_idx];
  
  if (p4d_table[p4d_idx] == 0) {
    addr_t *new_pud = malloc(512 * sizeof(addr_t));
    if (new_pud == NULL) { ret = -1; goto done; }
    memset(new_pud, 0, 512 * sizeof(addr_t));
    p4d_table[p4d_idx] = (addr_t)new_pud;
  }
  addr_t *pud_table = (addr_t *)p4d_table[p4d_idx];
  
  if (pud_table[pud_idx] == 0) {
    addr_t *new_pmd = malloc(512 * sizeof(addr_t));
    if (new_pmd == NULL) { ret = -1; goto done; }
    memset(new_pmd, 0, 512 * sizeof(addr_t));
    pud_table[pud_idx] = (addr_t)new_pmd;
  }
  addr_t *pmd_table = (addr_t *)pud_table[pud_idx];
  
  if (pmd_table[pmd_idx] == 0) {
    addr_t *new_pt = malloc(512 * sizeof(addr_t));
    if (new_pt == NULL) { ret = -1; goto done; }
    memset(new_pt, 0, 512 * sizeof(addr_t));
    pmd_table[pmd_idx] = (addr_t)new_pt;
  }
  addr_t *pt_table = (addr_t *)pmd_table[pmd_idx];
  
  pte = &pt_table[pt_idx];
#else
  pte = &mm->pgd[pgn];
#endif

  SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
  CLRBIT(*pte, PAGING_PTE_SWAPPED_MASK);
  SETVAL(*pte, fpn, PAGING_PTE_FPN_MASK, PAGING_PTE_FPN_LOBIT);

done:
  pthread_mutex_unlock(&mm->mm_lock);
  return ret;
}

/* Get PTE page table entry */
uint32_t pte_get_entry(struct pcb_t *caller, addr_t pgn)
{
  struct krnl_t *krnl = caller->krnl;
  struct mm_struct *mm = krnl->mm;
  uint32_t pte = 0;
  addr_t pgd_idx = 0, p4d_idx = 0, pud_idx = 0, pmd_idx = 0, pt_idx = 0;
  
  // LOCK
  pthread_mutex_lock(&mm->mm_lock);

  get_pd_from_pagenum(pgn, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);
  
  if (mm->pgd == NULL) { goto done; }
  
  if (mm->pgd[pgd_idx] == 0) { goto done; }
  addr_t *p4d_table = (addr_t *)mm->pgd[pgd_idx];
  
  if (p4d_table[p4d_idx] == 0) { goto done; }
  addr_t *pud_table = (addr_t *)p4d_table[p4d_idx];
  
  if (pud_table[pud_idx] == 0) { goto done; }
  addr_t *pmd_table = (addr_t *)pud_table[pud_idx];
  
  if (pmd_table[pmd_idx] == 0) { goto done; }
  addr_t *pt_table = (addr_t *)pmd_table[pmd_idx];
  
  pte = (uint32_t)pt_table[pt_idx];
  
done:
  // UNLOCK
  pthread_mutex_unlock(&mm->mm_lock);
  return pte;
}

/* Set PTE page table entry */
int pte_set_entry(struct pcb_t *caller, addr_t pgn, uint32_t pte_val)
{
  struct krnl_t *krnl = caller->krnl;
  struct mm_struct *mm = krnl->mm;
  addr_t pgd_idx = 0, p4d_idx = 0, pud_idx = 0, pmd_idx = 0, pt_idx = 0;
  int ret = 0;

  // LOCK
  pthread_mutex_lock(&mm->mm_lock);

#ifdef MM64
  get_pd_from_pagenum(pgn, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);
  
  if (mm->pgd == NULL) {
    mm->pgd = malloc(512 * sizeof(addr_t));
    if (mm->pgd == NULL) { ret = -1; goto done; }
    memset(mm->pgd, 0, 512 * sizeof(addr_t));
  }
  
  if (mm->pgd[pgd_idx] == 0) {
    addr_t *new_p4d = malloc(512 * sizeof(addr_t));
    if (new_p4d == NULL) { ret = -1; goto done; }
    memset(new_p4d, 0, 512 * sizeof(addr_t));
    mm->pgd[pgd_idx] = (addr_t)new_p4d;
  }
  addr_t *p4d_table = (addr_t *)mm->pgd[pgd_idx];
  
  if (p4d_table[p4d_idx] == 0) {
    addr_t *new_pud = malloc(512 * sizeof(addr_t));
    if (new_pud == NULL) { ret = -1; goto done; }
    memset(new_pud, 0, 512 * sizeof(addr_t));
    p4d_table[p4d_idx] = (addr_t)new_pud;
  }
  addr_t *pud_table = (addr_t *)p4d_table[p4d_idx];
  
  if (pud_table[pud_idx] == 0) {
    addr_t *new_pmd = malloc(512 * sizeof(addr_t));
    if (new_pmd == NULL) { ret = -1; goto done; }
    memset(new_pmd, 0, 512 * sizeof(addr_t));
    pud_table[pud_idx] = (addr_t)new_pmd;
  }
  addr_t *pmd_table = (addr_t *)pud_table[pud_idx];
  
  if (pmd_table[pmd_idx] == 0) {
    addr_t *new_pt = malloc(512 * sizeof(addr_t));
    if (new_pt == NULL) { ret = -1; goto done; }
    memset(new_pt, 0, 512 * sizeof(addr_t));
    pmd_table[pmd_idx] = (addr_t)new_pt;
  }
  addr_t *pt_table = (addr_t *)pmd_table[pmd_idx];
  
  pt_table[pt_idx] = pte_val;
#else
  mm->pgd[pgn] = pte_val;
#endif
  
done:
  // [UNLOCK]
  pthread_mutex_unlock(&mm->mm_lock);
  return ret;
}

/*
 * vmap_pgd_memset - map a range of page at aligned address
 */
int vmap_pgd_memset(struct pcb_t *caller, addr_t addr, int pgnum)
{
  struct krnl_t *krnl = caller->krnl;
  struct mm_struct *mm = krnl->mm;
  int pgit = 0;
  addr_t pgn;
  int ret = 0;

  // [LOCK]
  pthread_mutex_lock(&mm->mm_lock);

  for (pgit = 0; pgit < pgnum; pgit++) {
    pgn = (addr >> PAGING64_ADDR_PT_SHIFT) + pgit;
    
    addr_t pgd_idx = 0, p4d_idx = 0, pud_idx = 0, pmd_idx = 0, pt_idx = 0;
    get_pd_from_pagenum(pgn, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);
    
    if (mm->pgd == NULL) {
      mm->pgd = malloc(512 * sizeof(addr_t));
      if (mm->pgd == NULL) { ret = -1; goto done; }
      memset(mm->pgd, 0, 512 * sizeof(addr_t));
    }
    
    if (mm->pgd[pgd_idx] == 0) {
      addr_t *new_p4d = malloc(512 * sizeof(addr_t));
      if (new_p4d == NULL) { ret = -1; goto done; }
      memset(new_p4d, 0, 512 * sizeof(addr_t));
      mm->pgd[pgd_idx] = (addr_t)new_p4d;
    }
    addr_t *p4d_table = (addr_t *)mm->pgd[pgd_idx];
    
    if (p4d_table[p4d_idx] == 0) {
      addr_t *new_pud = malloc(512 * sizeof(addr_t));
      if (new_pud == NULL) { ret = -1; goto done; }
      memset(new_pud, 0, 512 * sizeof(addr_t));
      p4d_table[p4d_idx] = (addr_t)new_pud;
    }
    addr_t *pud_table = (addr_t *)p4d_table[p4d_idx];
    
    if (pud_table[pud_idx] == 0) {
      addr_t *new_pmd = malloc(512 * sizeof(addr_t));
      if (new_pmd == NULL) { ret = -1; goto done; }
      memset(new_pmd, 0, 512 * sizeof(addr_t));
      pud_table[pud_idx] = (addr_t)new_pmd;
    }
    addr_t *pmd_table = (addr_t *)pud_table[pud_idx];
    
    if (pmd_table[pmd_idx] == 0) {
      addr_t *new_pt = malloc(512 * sizeof(addr_t));
      if (new_pt == NULL) { ret = -1; goto done; }
      memset(new_pt, 0, 512 * sizeof(addr_t));
      pmd_table[pmd_idx] = (addr_t)new_pt;
    }
    addr_t *pt_table = (addr_t *)pmd_table[pmd_idx];
    
    pt_table[pt_idx] = 0xDEADBEEF; 
  }

done:
  // [UNLOCK]
  pthread_mutex_unlock(&mm->mm_lock);
  return ret;
}

/*
 * vmap_page_range - map a range of page at aligned address
 */
addr_t vmap_page_range(struct pcb_t *caller,
                     addr_t addr,
                     int pgnum,
                     struct framephy_struct *frames,
                     struct vm_rg_struct *ret_rg)
{
  int pgit = 0;
  addr_t pgn = addr >> PAGING64_ADDR_PT_SHIFT;

  ret_rg->rg_start = addr;
  ret_rg->rg_end = addr + pgnum * PAGING64_PAGESZ;
  
  /* Map range of frame to address space */
  for (pgit = 0; pgit < pgnum && frames != NULL; pgit++, frames = frames->fp_next) {
    pte_set_fpn(caller, pgn + pgit, frames->fpn);
    enlist_pgn_node(&caller->krnl->mm->fifo_pgn, pgn + pgit);
  }

  return 0;
}

/*
 * alloc_pages_range - allocate req_pgnum of frame in ram
 */
addr_t alloc_pages_range(struct pcb_t *caller, int req_pgnum, struct framephy_struct **frm_lst)
{
  int pgit;
  addr_t fpn;
  struct framephy_struct *newfp_str;
  struct framephy_struct *last_fp = NULL; 

   printf("liballoc %d \n ",req_pgnum);
  for(pgit = 0; pgit < req_pgnum; pgit++)
  {
    newfp_str = malloc(sizeof(struct framephy_struct));
    newfp_str->fp_next = NULL;
    newfp_str->owner = caller->krnl->mm;

    // 1. Thử lấy Frame trống từ RAM
    if (MEMPHY_get_freefp(caller->krnl->mram, &fpn) == 0) {
       newfp_str->fpn = fpn;
    } 
    else { 
       // 2. RAM đầy -> Phải Swap Out
       addr_t vicpgn, swpfpn;
       uint32_t vicpte;

       // Tìm nạn nhân 
       if (find_victim_page(caller->krnl->mm, &vicpgn) < 0) { 
           //  Không tìm được nạn nhân -> Cleanup và Return lỗi
           free(newfp_str); 
           goto alloc_error;
       }

       // Lấy thông tin frame của nạn nhân
       vicpte = pte_get_entry(caller, vicpgn);
       fpn = PAGING_FPN(vicpte);

       // Gán frame đó cho trang mới
       newfp_str->fpn = fpn;

       //  Kiểm tra xem có lấy được frame bên SWAP không
       if (MEMPHY_get_freefp(caller->krnl->active_mswp, &swpfpn) < 0) {
           // Lỗi: Swap cũng đầy -> Cleanup và Return lỗi
           free(newfp_str);
           goto alloc_error;
       }
       
       // Copy dữ liệu từ RAM (fpn) sang SWAP (swpfpn)
       __swap_cp_page(caller->krnl->mram, fpn, caller->krnl->active_mswp, swpfpn);

       // Cập nhật PTE của nạn nhân: Đánh dấu là đã SWAPPED
       pte_set_swap(caller, vicpgn, 0, swpfpn);
    }
    
    //  Chèn vào cuối danh sách (FIFO)
    if (*frm_lst == NULL) {
        *frm_lst = newfp_str;
    } else {
        last_fp->fp_next = newfp_str;
    }
    last_fp = newfp_str; // Cập nhật con trỏ đuôi
  }

  return 0;

alloc_error: {
  struct framephy_struct *temp = *frm_lst;
  while (temp != NULL) {
      struct framephy_struct *next = temp->fp_next;
      MEMPHY_put_freefp(caller->krnl->mram, temp->fpn); 
      free(temp);
      temp = next;
  }
  *frm_lst = NULL;
  return -3000;
}
}
/*
 * vm_map_ram - do the mapping all vm are to ram storage device
 */
addr_t vm_map_ram(struct pcb_t *caller, addr_t astart, addr_t aend, addr_t mapstart, int incpgnum, struct vm_rg_struct *ret_rg)
{
  struct framephy_struct *frm_lst = NULL;
  addr_t ret_alloc = 0;
  int pgnum = incpgnum;

  ret_alloc = alloc_pages_range(caller, pgnum, &frm_lst);

  if (ret_alloc < 0 && ret_alloc != -3000)
    return -1;

  if (ret_alloc == -3000)
  {
    return -1;
  }

  vmap_page_range(caller, mapstart, incpgnum, frm_lst, ret_rg);

  return 0;
}

/* Swap copy content page from source frame to destination frame */
int __swap_cp_page(struct memphy_struct *mpsrc, addr_t srcfpn,
                   struct memphy_struct *mpdst, addr_t dstfpn)
{
  int cellidx;
  addr_t addrsrc, addrdst;
  for (cellidx = 0; cellidx < PAGING64_PAGESZ; cellidx++)
  {
    addrsrc = srcfpn * PAGING64_PAGESZ + cellidx;
    addrdst = dstfpn * PAGING64_PAGESZ + cellidx;

    BYTE data;
    MEMPHY_read(mpsrc, addrsrc, &data);
    MEMPHY_write(mpdst, addrdst, data);
  }

  return 0;
}

/*
 * Initialize a empty Memory Management instance
 */
int init_mm(struct mm_struct *mm, struct pcb_t *caller)
{
  struct vm_area_struct *vma0 = malloc(sizeof(struct vm_area_struct));
  if (vma0 == NULL) return -1; 

  mm->pgd = NULL;
  mm->p4d = NULL;
  mm->pud = NULL;
  mm->pmd = NULL;
  mm->pt  = NULL;

  

  vma0->vm_id = 0;
  vma0->vm_start = 0;
  vma0->vm_end = vma0->vm_start;
  vma0->sbrk = vma0->vm_start;
  
  vma0->vm_freerg_list = NULL; 

  struct vm_rg_struct *first_rg = init_vm_rg(vma0->vm_start, vma0->vm_end);
  enlist_vm_rg_node(&vma0->vm_freerg_list, first_rg);

  vma0->vm_next = NULL;
  vma0->vm_mm = mm;
  mm->mmap = vma0;

  for (int i = 0; i < PAGING_MAX_SYMTBL_SZ; i++) {
     mm->symrgtbl[i].rg_start = 0;
     mm->symrgtbl[i].rg_end = 0;
     mm->symrgtbl[i].rg_next = NULL;
  }

  mm->fifo_pgn = NULL;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  // khoi tao RECURSIVE lock
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP); 

  pthread_mutex_init(&mm->mm_lock, &attr); 

  pthread_mutexattr_destroy(&attr);

  return 0;
}

struct vm_rg_struct *init_vm_rg(addr_t rg_start, addr_t rg_end)
{
  struct vm_rg_struct *rgnode = malloc(sizeof(struct vm_rg_struct));

  rgnode->rg_start = rg_start;
  rgnode->rg_end = rg_end;
  rgnode->rg_next = NULL;

  return rgnode;
}

int enlist_vm_rg_node(struct vm_rg_struct **rglist, struct vm_rg_struct *rgnode)
{
  rgnode->rg_next = *rglist;
  *rglist = rgnode;

  return 0;
}

int enlist_pgn_node(struct pgn_t **plist, addr_t pgn)
{
  struct pgn_t *pnode = malloc(sizeof(struct pgn_t));

  pnode->pgn = pgn;
  pnode->pg_next = *plist;
  *plist = pnode;

  return 0;
}

int print_list_fp(struct framephy_struct *ifp)
{
  struct framephy_struct *fp = ifp;

  printf("print_list_fp: ");
  if (fp == NULL) { printf("NULL list\n"); return -1;}
  printf("\n");
  while (fp != NULL)
  {
    printf("fp[" FORMAT_ADDR "]\n", fp->fpn);
    fp = fp->fp_next;
  }
  printf("\n");
  return 0;
}

int print_list_rg(struct vm_rg_struct *irg)
{
  struct vm_rg_struct *rg = irg;

  printf("print_list_rg: ");
  if (rg == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (rg != NULL)
  {
    printf("rg[" FORMAT_ADDR "->"  FORMAT_ADDR "]\n", rg->rg_start, rg->rg_end);
    rg = rg->rg_next;
  }
  printf("\n");
  return 0;
}

int print_list_vma(struct vm_area_struct *ivma)
{
  struct vm_area_struct *vma = ivma;

  printf("print_list_vma: ");
  if (vma == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (vma != NULL)
  {
    printf("va[" FORMAT_ADDR "->" FORMAT_ADDR "]\n", vma->vm_start, vma->vm_end);
    vma = vma->vm_next;
  }
  printf("\n");
  return 0;
}

/*
 * print_pgtbl - Dump the full page table with hierarchical values
 */
int print_pgtbl(struct pcb_t *caller, addr_t start, addr_t end)
{
  int i, j, k, l, m; 
  struct mm_struct *mm = caller->krnl->mm;

  if (!mm || !mm->pgd) {
      printf("print_pgtbl: PGD is NULL\n"); 
      return 0;
  }

  printf("print_pgtbl:\n");

  // 1. Duyệt PGD
  for (i = 0; i < 512; i++) {
    if (mm->pgd[i] == 0) continue;
    addr_t *p4d_base = (addr_t *)mm->pgd[i];
    
    // 2. Duyệt P4D
    for (j = 0; j < 512; j++) {
      if (p4d_base[j] == 0) continue;
      addr_t *pud_base = (addr_t *)p4d_base[j];
      
      // 3. Duyệt PUD
      for (k = 0; k < 512; k++) {
        if (pud_base[k] == 0) continue;
        addr_t *pmd_base = (addr_t *)pud_base[k];
        
        // 4. Duyệt PMD
        for (l = 0; l < 512; l++) {
          if (pmd_base[l] == 0) continue;
          addr_t *pt_base = (addr_t *)pmd_base[l];

          // 5. Duyệt PT (Page Table) - Chứa PTE
          for (m = 0; m < 512; m++) {
            if (pt_base[m] == 0) continue; 

            uint32_t pte = (uint32_t)pt_base[m]; 
            
            // [CẬP NHẬT] Thêm Off=%03x (chính là biến m)
            // m là index trong bảng PT (tương ứng với offset trang ảo)
            printf("\tPDG=%016llx P4g=%016llx PUD=%016llx PMD=%016llx PTE=%08x\n",
                   (uint64_t)mm->pgd[i],    
                   (uint64_t)p4d_base[j],   
                   (uint64_t)pud_base[k],   
                   (uint64_t)pmd_base[l],
                   pte,
                  m); // <--- In ra offset m (0 -> 511)
          }
        }
      }
    }
  }

  return 0;
}

#endif // defined(MM64)      pte_set_entry(caller, i, 0);
