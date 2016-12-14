#include "threadpool.h"

#include <pthread.h>
#include <stdlib.h>
#include <semaphore.h>

// The actual thread task
void *threadpool_worker(void *arg) {
    struct threadpool *pool = (struct threadpool *) arg;
    while (1) {
        sem_wait(pool->work_sem);
        if (pthread_mutex_lock(pool->lock) != 0) {
            continue;
        }
        if (!pool->active) {
            pthread_mutex_unlock(pool->lock);
            break;
        }
        // Pop off queue, unlock, then run
        struct q_elem *e = pool->exec_queue_head;
        if (e != NULL) {
            pool->exec_queue_head = e->next;
        }
        pthread_mutex_unlock(pool->lock);
        if (e != NULL) {
            e->func(e->arg);
            free(e);
        }
    }
    return NULL;
}

struct threadpool *threadpool_create(int num_threads) {
    // Initialize pool
    struct threadpool *pool = malloc(sizeof(struct threadpool));
    pool->lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(pool->lock, NULL);
    pool->work_sem = malloc(sizeof(sem_t));
    sem_init(pool->work_sem, 0, 0);
    pool->exec_queue_head = NULL;
    pool->active = 1;
    pool->num_threads = num_threads;
    // Start threads
    pool->threads = malloc(sizeof (pthread_t) * num_threads);
    int i;
    for (i = 0; i < num_threads; i++) {
        pthread_create(&pool->threads[i], NULL, &threadpool_worker, pool);
    }
    return pool;
}

void threadpool_submit(struct threadpool *pool,
        void *(*start_routine) (void *), void *arg) {
    if (pthread_mutex_lock(pool->lock) != 0) {
        // Just run it instead
        start_routine(arg);
        return;
    }
    struct q_elem *e = malloc(sizeof(struct q_elem));
    e->func = start_routine;
    e->arg = arg;
    e->next = NULL;
    // seek to the end and append
    struct q_elem *prev = pool->exec_queue_head;
    if (prev == NULL) {
        pool->exec_queue_head = e;
    } else {
        while (prev->next != NULL) {
            prev = prev->next;        
        }
        prev->next = e;
    }
    pthread_mutex_unlock(pool->lock);
    sem_post(pool->work_sem);
}

void threadpool_shutdown(struct threadpool *pool) {
    // Take control of the threadpool
    if (pthread_mutex_lock(pool->lock) != 0) {
        return;
    }
    // knock out the while loops (once we release lock)
    pool->active = 0;
    // clear queue
    struct q_elem *e = pool->exec_queue_head;
    while (e != NULL) {
        struct q_elem *next = e->next;
        free(e->arg);
        free(e);
        e = next;
    }
    pool->exec_queue_head = NULL;
    // let threads gain control and kill themselves
    pthread_mutex_unlock(pool->lock);
    
    int i;
    int num = pool->num_threads;

    // release each thread who is waiting on the semaphore
    for (i = 0; i < num; i++) {
        sem_post(pool->work_sem);
    }

    // Wait for all threads to die
    for (i = 0; i < num; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    // Cleanup
    free(pool->threads);
    free(pool->lock);
    free(pool->work_sem);
    free(pool);    
}

