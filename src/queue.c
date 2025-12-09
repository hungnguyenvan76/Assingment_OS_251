#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t *q)
{
    if (!q)
        return 1;
    return (q->size == 0);
}

void enqueue(struct queue_t *q, struct pcb_t *proc)
{
    if (!q || !proc)
        return;

    if (q->size >= MAX_QUEUE_SIZE)
        return;

    int insert_pos = q->size;

#ifdef MLQ_SCHED
    uint32_t new_prio = proc->prio;
#else
    uint32_t new_prio = proc->priority;
#endif

    for (int i = 0; i < q->size; i++) {
#ifdef MLQ_SCHED
        uint32_t ex_prio = q->proc[i]->prio;
#else
        uint32_t ex_prio = q->proc[i]->priority;
#endif
        if (new_prio < ex_prio) {
            insert_pos = i;
            break;
        }
    }

    for (int i = q->size; i > insert_pos; i--) {
        q->proc[i] = q->proc[i - 1];
    }

    q->proc[insert_pos] = proc;
    q->size++;
}

struct pcb_t *dequeue(struct queue_t *q)
{
    if (empty(q))
        return NULL;

    struct pcb_t *proc = q->proc[0];

    for (int i = 0; i < q->size - 1; i++) {
        q->proc[i] = q->proc[i + 1];
    }
    q->proc[q->size - 1] = NULL;
    q->size--;

    return proc;
}

struct pcb_t *purgequeue(struct queue_t *q, struct pcb_t *proc)
{
    if (!q || !proc)
        return NULL;

    int index = -1;

    for (int i = 0; i < q->size; i++) {
        if (q->proc[i] == proc) {
            index = i;
            break;
        }
    }

    if (index == -1)
        return NULL;

    for (int i = index; i < q->size - 1; i++) {
        q->proc[i] = q->proc[i + 1];
    }
    
    q->proc[q->size - 1] = NULL;
    q->size--;

    return proc;
}
