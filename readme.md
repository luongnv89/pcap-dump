[![Build Status](https://travis-ci.org/luongnv89/pcap_dump.svg?branch=master)](https://travis-ci.org/luongnv89/pcap_dump)

### Introduce

A common c/cpp api for dump network traffics as pcap file.

### API 

```
int pd_create(const char * path, int linktype, int thiszone, int snaplen);
```  
Create a new pcap file with specified `linktype`, `timezone` and `snaplen`. If the file does exist then it will open in append mode.


```
int pd_open(const char * path);
```  
Create a new pcap file with default configuration: `linktype = DLT_EN10MB`, `timezone = 0` and `snaplen = 65535`. If the file does exist then it will open in append mode.


```
int pd_write(int fd, char * buf,int len,struct timeval tv);
```  
Write a buffer into the pcap file


```
void pd_close(int fd);
```

Close a pcap file.  

### Install

No need to install it. Just include this file in your code and use the API.  

```
#include "pcap_dump.h"
```

### Usage

```
int fd = pd_open(fileName);

if(fd){
	pd_write(fd,(char*)data,caplen,ts);
	pd_close(fd);
}

```
### Notice 

If you want to write your own pcap dumper. Please notice the size of timestamp in pcap_header.
In x64 system, the size of `struct timeval` is 16. But in pcap format, the space for `struct timeval` is 8.
So you need to define your own pcap struct to avoid the possible mismatch bit.

### Contributors

- Based project has been created by [@NachtZ](https://github.com/NachtZ/pcapDumper)

### Change logs

- 20/04/2017: Add `dumpdump` example

- 20/04/2017: Fork project, add comments, update name convention (sorry @NachtZ but I prefer my convention), update readme.md