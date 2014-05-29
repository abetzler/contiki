#ifndef PROJECT_WORM_CONF_H_
#define PROJECT_WORM_CONF_H_

#undef CC2420_CONF_CCA_THRESH
#define CC2420_CONF_CCA_THRESH              0
#undef CC2420_CONF_AUTOACK
#define CC2420_CONF_AUTOACK                 0
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC                   nullrdc_driver
#undef NULLRDC_CONF_ADDRESS_FILTER
#define NULLRDC_CONF_ADDRESS_FILTER         0
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC                   nullmac_driver
#undef NETSTACK_CONF_LLSEC
#define NETSTACK_CONF_LLSEC                 wormsec_driver
#define LLSEC802154_CONF_SECURITY_LEVEL     2
#define LLSEC802154_CONF_USES_EXPLICIT_KEYS 1
#define LINKADDR_CONF_SIZE                  8

/* disable everything above the link layer */
#undef NETSTACK_CONF_NETWORK
#define NETSTACK_CONF_NETWORK               nullnet_driver
#undef UIP_CONF_TCP
#define UIP_CONF_TCP                        1
#undef UIP_CONF_UDP
#define UIP_CONF_UDP                        1
#undef WITH_UIP6
#define WITH_UIP6                           0

#endif /* PROJECT_WORM_CONF_H_ */
