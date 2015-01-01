#ifndef PROJECT_SIMPLE_UDP_CONF_H_
#define PROJECT_SIMPLE_UDP_CONF_H_

/* enable fragmentation support */
#define SICSLOWPAN_CONF_FRAG	1

/* Save some memory for the sky platform. */
#undef UIP_CONF_DS6_NBR_NBU
#define UIP_CONF_DS6_NBR_NBU     10
#undef UIP_CONF_DS6_ROUTE_NBU
#define UIP_CONF_DS6_ROUTE_NBU   10

#undef CC2420_CONF_CCA_THRESH
#define CC2420_CONF_CCA_THRESH 0

#if 0
#undef AES_128_CONF
#define AES_128_CONF aes_128_driver
#endif

#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC                 nullrdc_driver
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC                 nullmac_driver
#undef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM                 5
#undef LLSEC802154_CONF_SECURITY_LEVEL
#define LLSEC802154_CONF_SECURITY_LEVEL   2
#define APKES_CONF_SCHEME                 leap_apkes_scheme
#include "net/llsec/coresec/coresec-autoconf.h"

/* Disables TCP */
#define UIP_CONF_TCP 0

#endif /* PROJECT_SIMPLE_UDP_CONF_H_ */
