/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <unistd.h>  // Include POSIX API functions
#include <stdlib.h>  // Include standard library functions
#include "sender.h"  // Include the sender header
#include <daemon.h>  // Include daemon-related functions
#include <network/socket.h>  // Include socket functions
#include <processing/jobs/callback_job.h>  // Include callback job functions
#include <threading/thread.h>  // Include threading functions
#include <threading/condvar.h>  // Include condition variable functions
#include <threading/mutex.h>  // Include mutex functions
// Define a type for the private sender structure
typedef struct private_sender_t private_sender_t;
/**
 * Private data of a sender_t object.
 */
struct private_sender_t {
	/**
	 * Public part of a sender_t object.
	 */
	sender_t public;
	/**
	 * The packets are stored in a linked list
	 */
	linked_list_t *list;
	/**
	 * mutex to synchronize access to list
	 */
	mutex_t *mutex;
	/**
	 * condvar to signal for packets added to list
	 */
	condvar_t *got;
	/**
	 * condvar to signal for packets sent
	 */
	condvar_t *sent;
	/**
	 * Delay for sending outgoing packets, to simulate larger RTT
	 */
	int send_delay;
	/**
	 * Specific message type to delay, 0 for any
	 */
	int send_delay_type;
	/**
	 * Delay request messages?
	 */
	bool send_delay_request;
	/**
	 * Delay response messages?
	 */
	bool send_delay_response;
};
// Method to send a packet without adding Non-ESP marker
METHOD(sender_t, send_no_marker, void, private_sender_t *this, packet_t *packet) {
	// Lock the mutex to synchronize access to the list
	this->mutex->lock(this->mutex);
	// Insert the packet at the end of the list
	this->list->insert_last(this->list, packet);
	// Signal that a packet has been added to the list
	this->got->signal(this->got);
	// Unlock the mutex
	this->mutex->unlock(this->mutex);
}
// Method to send a packet with Non-ESP marker if needed
METHOD(sender_t, send_, void, private_sender_t *this, packet_t *packet) {
	// Declare pointers for source and destination hosts
	host_t *src, *dst;
	// Get the source and destination hosts from the packet
	src = packet->get_source(packet);
	dst = packet->get_destination(packet);
	// Log a debug message indicating the source and destination of the packet
	DBG1(DBG_NET, "sending packet: from %#H to %#H (%zu bytes)", src, dst, packet->get_data(packet).len);
	// Check if a send delay is configured
	if (this->send_delay) {
		// Declare a pointer for the message
		message_t *message;
		// Create a message from the packet
		message = message_create_from_packet(packet->clone(packet));
		// Parse the message header
		if (message->parse_header(message) == SUCCESS) {
			// Check if the message type matches the configured delay type
			if (this->send_delay_type == 0 ||
				this->send_delay_type == message->get_exchange_type(message)) {
				// Check if the message is a request or response and apply delay if needed
				if ((message->get_request(message) && this->send_delay_request) ||
					(!message->get_request(message) && this->send_delay_response)) {
					// Log a debug message indicating the send delay
					DBG1(DBG_NET, "using send delay: %dms", this->send_delay);
					// Sleep for the configured delay time
					usleep(this->send_delay * 1000);
				}
			}
		}
		// Destroy the message object
		message->destroy(message);
	}
	/* if neither source nor destination port is 500 we add a Non-ESP marker */
	// Check if neither source nor destination port is 500
	if (dst->get_port(dst) != IKEV2_UDP_PORT && src->get_port(src) != IKEV2_UDP_PORT) {
		// Declare a chunk for the packet data and the Non-ESP marker
		chunk_t data, marker = chunk_from_chars(0x00, 0x00, 0x00, 0x00);
		// Concatenate the marker and packet data
		data = chunk_cat("cc", marker, packet->get_data(packet));
		// Set the new data for the packet
		packet->set_data(packet, data);
	}
	// Send the packet without adding a Non-ESP marker
	send_no_marker(this, packet);
}
/**
 * Job callback function to send packets
 */
static job_requeue_t send_packets(private_sender_t *this) {
	// Declare a pointer for the packet
	packet_t *packet;
	// Declare a boolean for the old thread cancelability state
	bool oldstate;
	// Lock the mutex to synchronize access to the list
	this->mutex->lock(this->mutex);
	// Wait for packets to be added to the list
	while (this->list->get_count(this->list) == 0) {
		/* add cleanup handler, wait for packet, remove cleanup handler */
		// Push a cleanup handler to release the mutex in case of thread cancellation
		thread_cleanup_push((thread_cleanup_t)this->mutex->unlock, this->mutex);
		// Enable thread cancelability and save the old state
		oldstate = thread_cancelability(TRUE);
		// Wait for the condition variable to be signaled
		this->got->wait(this->got, this->mutex);
		// Restore the old thread cancelability state
		thread_cancelability(oldstate);
		// Pop the cleanup handler without executing it
		thread_cleanup_pop(FALSE);
	}
	// Remove the first packet from the list
	this->list->remove_first(this->list, (void**)&packet);
	// Signal that a packet has been sent
	this->sent->signal(this->sent);
	// Unlock the mutex
	this->mutex->unlock(this->mutex);
	// Send the packet using the charon socket
	charon->socket->send(charon->socket, packet);
	// Destroy the packet object
	packet->destroy(packet);
	// Return JOB_REQUEUE_DIRECT to indicate the job should be requeued
	return JOB_REQUEUE_DIRECT;
}
// Method to flush the send queue
METHOD(sender_t, flush, void, private_sender_t *this) {
	/* send all packets in the queue */
	// Lock the mutex to synchronize access to the list
	this->mutex->lock(this->mutex);
	// Wait for the send queue to be empty
	while (this->list->get_count(this->list)) {
		// Wait for the condition variable to be signaled
		this->sent->wait(this->sent, this->mutex);
	}
	// Unlock the mutex
	this->mutex->unlock(this->mutex);
}
// Method to destroy the sender object
METHOD(sender_t, destroy, void,	private_sender_t *this) {
	// Destroy all packets in the list using the destroy method of packet_t
	this->list->destroy_offset(this->list, offsetof(packet_t, destroy));
	// Destroy the condition variables and mutex
	this->got->destroy(this->got);
	this->sent->destroy(this->sent);
	this->mutex->destroy(this->mutex);
	// Free the private sender structure
	free(this);
}
/*
 * Described in header.
 */
// Function to create a sender object
sender_t * sender_create() {
	// Declare a pointer for the private sender structure
	private_sender_t *this;
	// Initialize the private sender structure
	INIT(this,
		.public = {
			.send = _send_,  // Set the send method
			.send_no_marker = _send_no_marker,  // Set the send_no_marker method
			.flush = _flush,  // Set the flush method
			.destroy = _destroy,  // Set the destroy method
		},
		.list = linked_list_create(),  // Create a linked list for packets
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),  // Create a mutex
		.got = condvar_create(CONDVAR_TYPE_DEFAULT),  // Create a condition variable for packets added
		.sent = condvar_create(CONDVAR_TYPE_DEFAULT),  // Create a condition variable for packets sent
		// Get the send delay configuration from settings
		.send_delay = lib->settings->get_int(lib->settings, "%s.send_delay", 0, lib->ns),
		// Get the send delay type configuration from settings
		.send_delay_type = lib->settings->get_int(lib->settings,"%s.send_delay_type", 0, lib->ns),
		// Get the send delay request configuration from settings
		.send_delay_request = lib->settings->get_bool(lib->settings,"%s.send_delay_request", TRUE, lib->ns),
		// Get the send delay response configuration from settings
		.send_delay_response = lib->settings->get_bool(lib->settings, "%s.send_delay_response", TRUE, lib->ns),
	);
	// Queue the send_packets job with critical priority
	lib->processor->queue_job(lib->processor, (job_t*)callback_job_create_with_prio((callback_job_cb_t)send_packets,	this, NULL, (callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));
	// Return the public part of the sender structure
	return &this->public;
}