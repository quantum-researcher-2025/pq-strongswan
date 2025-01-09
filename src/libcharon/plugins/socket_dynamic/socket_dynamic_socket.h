/*
 * Copyright (C) 2010 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup socket_dynamic_socket socket_dynamic_socket
 * @{ @ingroup socket_dynamic
 */
#ifndef SOCKET_DYNAMIC_SOCKET_H_
    #define SOCKET_DYNAMIC_SOCKET_H_
    // Define a type for the socket dynamic socket structure
    typedef struct socket_dynamic_socket_t socket_dynamic_socket_t;
    #include <network/socket.h> // Include the necessary header for the socket interface
    /**
     * A socket implementation binding to ports on demand as required.
     */
    struct socket_dynamic_socket_t {
        /**
         * Implements the socket_t interface.
         */
        socket_t socket; // The socket interface implementation
    };
    /**
     * Create a socket_dynamic_socket instance.
     */
    socket_dynamic_socket_t *socket_dynamic_socket_create();
#endif /** SOCKET_DYNAMIC_SOCKET_H_ @}*/