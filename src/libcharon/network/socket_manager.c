/*
 * Copyright (C) 2010-2012 Tobias Brunner
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

#include "socket_manager.h"  // Include the header file for the socket manager
#include <daemon.h>  // Include daemon-related functions
#include <threading/thread.h>  // Include threading functions
#include <threading/rwlock.h>  // Include read-write lock functions
#include <collections/linked_list.h>  // Include linked list functions
// Define a type for the private socket manager structure
typedef struct private_socket_manager_t private_socket_manager_t;
/**
 * Private data of an socket_manager_t object.
 */
struct private_socket_manager_t {
	/**
	 * Public socket_manager_t interface.
	 */
	socket_manager_t public;  // The public part of the structure implementing the socket manager interface
	/**
	 * List of registered socket constructors
	 */
	linked_list_t *sockets;  // Linked list to store registered socket constructors
	/**
	 * Instantiated socket implementation
	 */
	socket_t *socket;  // Pointer to the instantiated socket implementation
	/**
	 * The constructor used to create the current socket
	 */
	socket_constructor_t create;  // The constructor function used to create the current socket
	/**
	 * Lock for sockets list
	 */
	rwlock_t *lock;  // Read-write lock for the sockets list
};
// Method to receive packets
METHOD(socket_manager_t, receiver, status_t, private_socket_manager_t *this, packet_t **packet) {
	// Declare a variable for the status
	status_t status;
	// Acquire a read lock on the sockets list
	this->lock->read_lock(this->lock);
	// Check if no socket implementation is registered
	if (!this->socket) {
		// Log a debug message indicating no socket implementation is registered
		DBG1(DBG_NET, "no socket implementation registered, receiving failed");
		// Release the read lock
		this->lock->unlock(this->lock);
		// Return NOT_SUPPORTED status
		return NOT_SUPPORTED;
	}
	/* receive is blocking and the thread can be canceled */
	// Push a cleanup handler to release the read lock in case of thread cancellation
	thread_cleanup_push((thread_cleanup_t)this->lock->unlock, this->lock);
	// Receive a packet using the registered socket implementation
	status = this->socket->receive(this->socket, packet);
	// Pop the cleanup handler and execute it (release the read lock)
	thread_cleanup_pop(TRUE);
	// Return the status of the receive operation
	return status;
}
// Method to send packets
METHOD(socket_manager_t, sender, status_t, private_socket_manager_t *this, packet_t *packet) {
	// Declare a variable for the status
	status_t status;
	// Acquire a read lock on the sockets list
	this->lock->read_lock(this->lock);
	// Check if no socket implementation is registered
	if (!this->socket) {
		// Log a debug message indicating no socket implementation is registered
		DBG1(DBG_NET, "no socket implementation registered, sending failed");
		// Release the read lock
		this->lock->unlock(this->lock);
		// Return NOT_SUPPORTED status
		return NOT_SUPPORTED;
	}
	// Send the packet using the registered socket implementation
	status = this->socket->send(this->socket, packet);
	// Release the read lock
	this->lock->unlock(this->lock);
	// Return the status of the send operation
	return status;
}
// Method to get the port
METHOD(socket_manager_t, get_port, uint16_t, private_socket_manager_t *this, bool nat_t) {
	// Declare a variable for the port, initialized to 0
	uint16_t port = 0;
	// Acquire a read lock on the sockets list
	this->lock->read_lock(this->lock);
	// Check if a socket implementation is registered
	if (this->socket) {
		// Get the port from the registered socket implementation
		port = this->socket->get_port(this->socket, nat_t);
	}
	// Release the read lock
	this->lock->unlock(this->lock);
	// Return the port
	return port;
}
// Method to get the supported address families
METHOD(socket_manager_t, supported_families, socket_family_t, private_socket_manager_t *this) {
	// Declare a variable for the supported families, initialized to none
	socket_family_t families = SOCKET_FAMILY_NONE;
	// Acquire a read lock on the sockets list
	this->lock->read_lock(this->lock);
	// Check if a socket implementation is registered
	if (this->socket) {
		// Get the supported families from the registered socket implementation
		families = this->socket->supported_families(this->socket);
	}
	// Release the read lock
	this->lock->unlock(this->lock);
	// Return the supported families
	return families;
}
// Function to create a socket
static void create_socket(private_socket_manager_t *this) {
	// Declare a variable for the socket constructor
	socket_constructor_t create;
	/* remove constructors in order to avoid trying to create broken ones
	 * multiple times */
	// Remove constructors from the list and try to create a socket
	while (this->sockets->remove_first(this->sockets, (void**)&create) == SUCCESS)	{
		// Create a socket using the constructor
		this->socket = create();
		// If a socket is created successfully
		if (this->socket) {
			// Store the constructor used to create the socket
			this->create = create;
			// Break the loop as we have successfully created a socket
			break;
		}
	}
}
// Method to add a socket constructor
METHOD(socket_manager_t, add_socket, void, private_socket_manager_t *this, socket_constructor_t create) {
	// Acquire a write lock on the sockets list
	this->lock->write_lock(this->lock);
	// Insert the socket constructor at the end of the list
	this->sockets->insert_last(this->sockets, create);
	// If no socket implementation is registered, create a socket
	if (!this->socket) {
		create_socket(this);
	}
	// Release the write lock
	this->lock->unlock(this->lock);
}
// Method to remove a socket constructor
METHOD(socket_manager_t, remove_socket, void, private_socket_manager_t *this, socket_constructor_t create) {
	// Acquire a write lock on the sockets list
	this->lock->write_lock(this->lock);
	// Remove the socket constructor from the list
	this->sockets->remove(this->sockets, create, NULL);
	// Check if the current socket was created using the constructor to be removed
	if (this->create == create)	{
		// Destroy the current socket implementation
		this->socket->destroy(this->socket);
		// Set the socket and create pointers to NULL
		this->socket = NULL;
		this->create = NULL;
		// Attempt to create a new socket with remaining constructors
		create_socket(this);
	}
	// Release the write lock
	this->lock->unlock(this->lock);
}
// Method to destroy the socket manager
METHOD(socket_manager_t, destroy, void,	private_socket_manager_t *this) {
	// Destroy the current socket implementation if it exists
	DESTROY_IF(this->socket);
	// Destroy the list of socket constructors
	this->sockets->destroy(this->sockets);
	// Destroy the read-write lock
	this->lock->destroy(this->lock);
	// Free the private socket manager structure
	free(this);
}
/**
 * See header
 */
// Function to create a socket manager instance
socket_manager_t *socket_manager_create() {
	// Declare a pointer for the private socket manager structure
	private_socket_manager_t *this;
	// Initialize the private socket manager structure
	INIT(this,
		.public = {
			.send = _sender,                 // Set the send method
			.receive = _receiver,            // Set the receive method
			.get_port = _get_port,           // Set the get_port method
			.supported_families = _supported_families,  // Set the supported_families method
			.add_socket = _add_socket,       // Set the add_socket method
			.remove_socket = _remove_socket, // Set the remove_socket method
			.destroy = _destroy,             // Set the destroy method
		},
		.sockets = linked_list_create(),    // Create a linked list for socket constructors
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT), // Create a read-write lock
	);
	// Return the public part of the socket manager structure
	return &this->public;
}