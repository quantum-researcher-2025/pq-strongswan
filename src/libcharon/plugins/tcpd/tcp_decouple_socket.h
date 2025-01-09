//
// Created by RIT WISP on 3/8/24.
//

#ifndef TCP_DECOUPLE_SOCKET_H_
#define TCP_DECOUPLE_SOCKET_H_

typedef struct tcp_decouple_socket tcp_decouple_socket;

#include <network/socket.h>
/**
 * A socket implementation binding to TCP for 4500 for IKE Messages.
 */
struct tcp_decouple_socket {
    /**
     * Implements the socket_t interface.
     */
    socket_t socket;
};
/**
 * Create a tcp_decouple_socket instance.
 */
tcp_decouple_socket *tcp_decouple_socket_create();
#endif /** TCP_DECOUPLE_SOCKET_H_ @}*/