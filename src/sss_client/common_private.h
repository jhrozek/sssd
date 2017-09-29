
#include "config.h"

#if HAVE_PTHREAD
#include <pthread.h>

struct sss_mutex {
    pthread_mutex_t mtx;

    int old_cancel_state;
};

#endif
