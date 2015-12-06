// the extent server implementation

#include "extent_server.h"
#include <sstream>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * Directory format:
 * <size>
 * <inode> <filename>
 * <inode> <filename>
 * ...
 * <inode> <filename>
 */
extent_server::extent_server() {
    /* initialize stuff here, make sure to create
     * an entry for the root of the filesystem */
    extent_protocol::extentid_t rootid = 0x00000001;
    extent_protocol::attr rootattr;
    rootattr.atime = rootattr.ctime = rootattr.mtime = time(NULL);
    std::string rootdir = "0\n";
    rootattr.size = rootdir.length();

    /* add to attrmap and contmap */
    attrmap[rootid] = rootattr;
    contmap[rootid] = rootdir;
    printf("create root directory\n");
}

int extent_server::put(extent_protocol::extentid_t id, std::string buf, int &r)
{
    printf("put %d\n", id);
    extent_protocol::attr attr;
    if (attrmap.find(id) == attrmap.end()) {
        return extent_protocol::NOENT;
    }

    attr = attrmap[id];
    attr.atime = attr.mtime = time(NULL);
    attr.size = buf.length();
    attrmap[id] = attr;
    contmap[id] = buf;

    return extent_protocol::OK;	
}

int extent_server::get(extent_protocol::extentid_t id, std::string &buf)
{
    printf("get %d\n", id);
    extent_protocol::attr attr;
    if (contmap.find(id) == contmap.end()) {
        return extent_protocol::NOENT;	
    }

    attr = attrmap[id];
    buf = contmap[id];
    attr.atime = time(NULL);
    return extent_protocol::OK;
}

int extent_server::getattr(extent_protocol::extentid_t id, extent_protocol::attr &a)
{
    printf("getattr %d\n", id);
    if (attrmap.find(id) != attrmap.end()) {
        a = attrmap[id];
        return extent_protocol::OK;
    }
    return extent_protocol::NOENT;

}

int extent_server::remove(extent_protocol::extentid_t id, int &)
{
    printf("remove %d\n", id);
    std::map<extent_protocol::extentid_t, std::string>::iterator cit;
    std::map<extent_protocol::extentid_t, extent_protocol::attr>::iterator ait;
    cit = contmap.find(id);
    ait = attrmap.find(id);
    if (cit == contmap.end()) {
        return extent_protocol::NOENT;
    }

    contmap.erase(cit);
    attrmap.erase(ait);

    /* find a directory containing this file */

    return extent_protocol::OK;
}

int extent_server::create(extent_protocol::extentid_t parent, std::string filename, extent_protocol::extentid_t &ino)
{
    printf("create %s in %d\n", filename.c_str(), parent);
    if (parent & 0x80000000) {
        return extent_protocol::NOENT;
    }

    if (attrmap.find(parent) == attrmap.end()) {
        return extent_protocol::NOENT;
    }

    extent_protocol::attr pattr = attrmap[parent];
    std::string &dir = contmap[parent];
    std::stringstream ss(dir);
    std::stringstream nss;

    ino = rand() | 0x80000000;

    int i, n;
    ss >> n;
    nss << n+1 << "\n";

    for (i = 0; i < n; i++) {
        extent_protocol::extentid_t id;
        std::string name;
        ss >> id;
        ss >> name;
        nss << id << " " << name << "\n";
    }

    nss << ino << " " << filename << "\n";

    extent_protocol::attr attr;
    std::string cont = "";
    pattr.atime = pattr.mtime = attr.atime = attr.ctime = attr.mtime = time(NULL);
    attr.size = 0;

    attrmap[parent] = pattr;
    contmap[parent] = nss.str();

    attrmap[ino] = attr;
    contmap[ino] = cont;

    printf("create done\n");
    return extent_protocol::OK;
}

int extent_server::lookup(extent_protocol::extentid_t parent, std::string filename, extent_protocol::extentid_t &ino)
{
    printf("lookup %s in %d\n", filename.c_str(), parent);
    if (parent & 0x80000000) {
        printf("parent is not a directory\n");
        return extent_protocol::NOENT;
    }

    if (attrmap.find(parent) == attrmap.end()) {
        printf("parent does not exist\n");
        return extent_protocol::NOENT;
    }

    extent_protocol::attr pattr = attrmap[parent];
    pattr.atime = time(NULL);
    attrmap[parent] = pattr;
    std::string &dir = contmap[parent];
    std::stringstream ss(dir);

    int i, n;
    ss >> n;

    extent_protocol::extentid_t id;
    for (i = 0; i < n; i++) {
        std::string name;
        ss >> id;
        ss >> name;
        if (name == filename) {
            break;
        }
    }

    if (i == n) {
        ino = 0;
        printf("file does not exist in parent\n");
        return extent_protocol::NOENT;
    }

    ino = id;
    printf("file has been found\n");
    return extent_protocol::OK;
}
