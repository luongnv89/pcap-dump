VERSION  := 1.0.0.0
GIT_VERSION := $(shell git log --format="%h" -n 1)

CPP = gcc

CFLAGS = -Wall -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\"
LIBS = -lpcap

# Define DEBUG
ifdef DEBUG
	CFLAGS += -g -DDEBUG
else
	CFLAGS += -O3
endif

APP = dumpdump
SRC =   pcap_dump.c \
		dumpdump.c

all:
	$(CPP) -o $(APP) $(SRC) $(CFLAGS) $(LIBS)
test:
	./$(APP) -t dhcp.pcap -o new_dhcp.pcap
	