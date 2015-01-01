CONTIKI_PROJECT = broadcast-example
all: $(CONTIKI_PROJECT)

CONTIKI=../../../..

UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"
APPS=servreg-hack
SMALL=1

include $(CONTIKI)/Makefile.include
