// yfs client.  implements FS operations using extent and lock server
#include "yfs_client.h"
#include "extent_client.h"
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


yfs_client::yfs_client(std::string extent_dst, std::string lock_dst)
{
    ec = new extent_client(extent_dst);
}

yfs_client::inum
yfs_client::n2i(std::string n)
{
    std::istringstream ist(n);
    unsigned long long finum;
    ist >> finum;
    return finum;
}

std::string
yfs_client::filename(inum inum)
{
    std::ostringstream ost;
    ost << inum;
    return ost.str();
}

bool
yfs_client::isfile(inum inum)
{
    if(inum & 0x80000000)
        return true;
    return false;
}

bool
yfs_client::isdir(inum inum)
{
    return ! isfile(inum);
}

int
yfs_client::getfile(inum inum, fileinfo &fin)
{
    int r = OK;


    printf("getfile %016llx\n", inum);
    extent_protocol::attr a;
    if (ec->getattr(inum, a) != extent_protocol::OK) {
        r = IOERR;
        goto release;
    }

    fin.atime = a.atime;
    fin.mtime = a.mtime;
    fin.ctime = a.ctime;
    fin.size = a.size;
    printf("getfile %016llx -> sz %llu\n", inum, fin.size);

release:

    return r;
}

int
yfs_client::getdir(inum inum, dirinfo &din)
{
    int r = OK;


    printf("getdir %016llx\n", inum);
    extent_protocol::attr a;
    if (ec->getattr(inum, a) != extent_protocol::OK) {
        r = IOERR;
        goto release;
    }
    din.atime = a.atime;
    din.mtime = a.mtime;
    din.ctime = a.ctime;

release:
    return r;
}

int
yfs_client::get(inum inum, std::string &buf)
{
    int r = OK;

    printf("get %016llx\n", inum);
    if (ec->get(inum, buf) != extent_protocol::OK) {
        r = IOERR;
    }

    return r;
}

int
yfs_client::create(inum parent, std::string name, inum &ino)
{
    printf("create %016llx %s\n", parent, name.c_str());
    if (ec->create(parent, name, ino) != extent_protocol::OK) {
        return IOERR;
    }

    return OK;
}

int
yfs_client::lookup(inum parent, std::string name, inum &ino)
{
    if (ec->lookup(parent, name, ino) != extent_protocol::OK) {
        return NOENT;
    }

    return OK;
}

int
yfs_client::setfile(inum inum, off_t size)
{
    printf("setfile %016llx to %lld\n", inum, size);
    extent_protocol::attr a;
    a.size = size;
    a.atime = a.mtime = a.ctime = 0;
    if (ec->setattr(inum, a) != extent_protocol::OK) {
        return IOERR;
    }

    return OK;
}

int
yfs_client::read(inum inum, off_t off, size_t size, std::string &buf)
{
    printf("read %016llx at %lld\n", inum, off);
    if (ec->read(inum, off, size, buf) != extent_protocol::OK) {
        return IOERR;
    }

    return OK;
}

int
yfs_client::write(inum inum, off_t off, size_t size, std::string buf, int &nwritten)
{
    printf("write %016llx at %lld\n", inum, off);
    if (ec->write(inum, off, size, buf, nwritten) != extent_protocol::OK) {
        return IOERR;
    }

    return OK;
}
