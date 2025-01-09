//
// Created by RIT WISP on 3/8/24.
//

#ifndef TCP_DECOUPLE_PLUGIN_H_
#define TCP_DECOUPLE_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct tcp_decouple_plugin_t tcp_decouple_plugin_t;

/**
 * TCP Decouple plugin.
 *
 * This plugin subscribes a listener to the IKE message hook and provides
 * the encapsulation of further IKE messaging within the TCP connection.
 */
struct tcp_decouple_plugin_t {

    /**
     * implements plugin interface
     */
    plugin_t plugin;
};

#endif /** TCP_DECOUPLE_PLUGIN_H_ @}*/