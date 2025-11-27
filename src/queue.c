#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t *q)
{
    if (q == NULL)
        return 1;
    return (q->size == 0);
}

void enqueue(struct queue_t *q, struct pcb_t *proc)
{
    // Kiểm tra xem hàng đợi có đầy không 
    if (q->size >= MAX_QUEUE_SIZE) 
        return;
    
    // Sửa lỗi: Truy cập mảng proc bên trong struct q, dùng q->size 
    q->proc[q->size] = proc;
    q->size++;
}

struct pcb_t *dequeue(struct queue_t *q)
{
    if (empty(q))
        return NULL;

    // Logic tìm phần tử ưu tiên cao nhất 
    int best_index = 0;
    
    // Lấy phần tử đầu tiên làm mốc so sánh 
    struct pcb_t *best_proc = q->proc[0];

    for (int i = 1; i < q->size; ++i) {

        // Nếu MLQ_SCHED được định nghĩa, dùng 'prio'. Nếu không, dùng 'priority'.
        uint32_t current_prio_val, best_prio_val;

#ifdef MLQ_SCHED
        current_prio_val = q->proc[i]->prio;
        best_prio_val = best_proc->prio;
#else
        current_prio_val = q->proc[i]->priority;
        best_prio_val = best_proc->priority;
#endif

        if (current_prio_val < best_prio_val) {
            best_proc = q->proc[i];
            best_index = i;
        }
    }

    // Sau khi tìm được, xóa khỏi hàng đợi và trả về 
    // Dồn mảng để lấp vị trí vừa lấy ra
    for (int i = best_index; i < q->size - 1; ++i) {
        q->proc[i] = q->proc[i+1];
    }
    
    q->proc[q->size - 1] = NULL; // Xóa process thừa
    q->size--;

    return best_proc;
}

struct pcb_t *purgequeue(struct queue_t *q, struct pcb_t *proc)
{
    int index = -1;

    // Tìm vị trí của process 
    for (int i = 0; i < q->size; ++i) {
        if (proc == q->proc[i]) {
            index = i;
            break;
        }
    }

    if (index == -1)
        return NULL;

    // Dồn hàng đợi 
    for (int i = index; i < q->size - 1; ++i) {
        q->proc[i] = q->proc[i+1];
    }

    q->proc[q->size - 1] = NULL;
    q->size--;

    return proc;
}
