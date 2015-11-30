// the extent server implementation

#include "extent_server.h"
#include <sstream>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

extent_server::extent_server() {
/*initialize stuff here, make sure to create
 *an entry for the root of the filesystem*/
}

int extent_server::put(extent_protocol::extentid_t id, std::string buf, int &)
{
	return extent_protocol::NOENT;	
}

int extent_server::get(extent_protocol::extentid_t id, std::string &buf)
{
	return extent_protocol::NOENT;	
}

int extent_server::getattr(extent_protocol::extentid_t id, extent_protocol::attr &a)
{
  if(attrmap.find(id) != attrmap.end()){
	a = attrmap[id];
	return extent_protocol::OK;
  }else{
	return extent_protocol::NOENT;
  }

}

int extent_server::remove(extent_protocol::extentid_t id, int &)
{
	return extent_protocol::NOENT;
}

