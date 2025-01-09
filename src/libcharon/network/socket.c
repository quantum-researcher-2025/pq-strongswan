/*
 * Copyright (C) 2011 Martin Willi
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

#include "socket.h"  // Include the header file for the socket interface

#include <daemon.h>  // Include the daemon-related functions header

/**
 * See header
 */
// Function to register or unregister a socket interface from plugin features
bool socket_register(plugin_t *plugin, plugin_feature_t *feature, bool reg, void *data) {
	// If reg is TRUE, register the socket interface constructor
	if (reg) {
		// Add the socket constructor to the charon's socket manager
		charon->socket->add_socket(charon->socket, (socket_constructor_t)data);
	}
	// If reg is FALSE, unregister the socket interface constructor
	else {
		// Remove the socket constructor from the charon's socket manager
		charon->socket->remove_socket(charon->socket,
									  (socket_constructor_t)data);
	}
	// Return TRUE to indicate success
	return TRUE;
}