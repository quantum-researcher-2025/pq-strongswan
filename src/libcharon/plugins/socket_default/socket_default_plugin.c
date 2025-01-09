/*
 * Copyright (C) 2010 Tobias Brunner
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

#include "socket_default_plugin.h"  // Include the header file for the socket default plugin
#include "socket_default_socket.h"  // Include the header file for the socket default socket
#include <daemon.h>  // Include the header file for daemon-related functions
// Define a type for the private socket default plugin structure
typedef struct private_socket_default_plugin_t private_socket_default_plugin_t;
/**
 * Private data of socket plugin
 */
struct private_socket_default_plugin_t {
	/**
	 * Implements plugin interface
	 */
	socket_default_plugin_t public;  // The public part of the structure, implementing the plugin interface
};
// Method to get the name of the plugin
METHOD(plugin_t, get_name, char*, private_socket_default_plugin_t *this) {
	// Return the name of the plugin
	return "socket-default";
}
// Method to destroy the plugin
METHOD(plugin_t, destroy, void, private_socket_default_plugin_t *this) {
	// Free the memory allocated for the private socket default plugin structure
	free(this);
}
// Method to get the features of the plugin
METHOD(plugin_t, get_features, int,	private_socket_default_plugin_t *this, plugin_feature_t *features[]) {
	// Define a static array of plugin features
	static plugin_feature_t f[] = {
		// Register a callback for socket creation
		PLUGIN_CALLBACK(socket_register, socket_default_socket_create),
		// Provide a custom feature named "socket"
		PLUGIN_PROVIDE(CUSTOM, "socket"),
		// Specify a soft dependency on the "kernel-ipsec" feature
		PLUGIN_SDEPEND(CUSTOM, "kernel-ipsec"),
	};
	// Set the features pointer to the array of features
	*features = f;
	// Return the number of features
	return countof(f);
}
/*
 * see header file
 */
// Function to create a socket default plugin instance
plugin_t *socket_default_plugin_create() {
	// Declare a pointer to the private socket default plugin structure
	private_socket_default_plugin_t *this;
	// Initialize the private socket default plugin structure
	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,        // Set the get_name method
				.get_features = _get_features,// Set the get_features method
				.destroy = _destroy,          // Set the destroy method
			},
		},
	);
	// Return the public plugin interface
	return &this->public.plugin;
}