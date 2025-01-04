#include <pthread.h>

void *foo(void *v) {
    return NULL;
}

int main() {
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, foo, NULL);
    return pthread_join(thread, NULL);
}
