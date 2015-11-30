// the lock server implementation

#include "lock_server.h"
#include <sstream>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

lock_server::lock_server()
    : nacquire (0)
{
    assert(pthread_mutex_init(&lock_map_mtx, NULL) == 0);
}

lock_server::~lock_server()
{
    std::map<lock_protocol::lockid_t, pthread_mutex_t *>::iterator it;
    for (it = lock_map.begin(); it != lock_map.end(); it++) {
        pthread_mutex_unlock(it->second);
        assert(pthread_mutex_destroy(it->second));
        delete it->second;
    }
    lock_map.clear();
    assert(pthread_mutex_destroy(&lock_map_mtx) == 0);
}

lock_protocol::status
lock_server::acquire(lock_protocol::lockid_t lid, int &r)
{
    pthread_mutex_t *lock;

    assert(pthread_mutex_lock(&lock_map_mtx) == 0);
    if (lock_map.count(lid) == 0) {
        lock = new pthread_mutex_t;
        assert(pthread_mutex_init(lock, NULL) == 0);
        lock_map[lid] = lock;
    } else {
        lock = lock_map[lid];
    }

    assert(pthread_mutex_unlock(&lock_map_mtx) == 0);
    assert(pthread_mutex_lock(lock) == 0);
    r = 0;
    return lock_protocol::OK;
}

lock_protocol::status
lock_server::release(lock_protocol::lockid_t lid, int &r)
{
    if (lock_map.count(lid) == 0) {
        return lock_protocol::NOENT;
    }

    assert(pthread_mutex_unlock(lock_map[lid]) == 0);
    r = 0;
    return lock_protocol::OK;
}

lock_protocol::status
lock_server::stat(int clt, lock_protocol::lockid_t lid, int &r)
{
    lock_protocol::status ret = lock_protocol::OK;
    printf("stat request from clt %d\n", clt);
    r = nacquire;
    return ret;
}


