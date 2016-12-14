#include <pthread.h>
#include <semaphore.h>

// Element in queue for jobs to be processed
struct q_elem {
    void *(*func) (void *);
    void *arg;
    struct q_elem *next;
};

// The pool
struct threadpool {
    int num_threads;
    pthread_t *threads;
    struct q_elem *exec_queue_head;
    pthread_mutex_t *lock;
    int active;
    sem_t *work_sem;
};

struct threadpool *threadpool_create(int num_threads);

void threadpool_shutdown(struct threadpool *pool);

void threadpool_submit(struct threadpool *pool,
        void *(*start_routine) (void *), void *arg);

