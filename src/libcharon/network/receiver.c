/*
 * Copyright (C) 2008-2012 Tobias Brunner
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

#include <stdlib.h>  // Include standard library functions
#include <unistd.h>  // Include POSIX API functions
#include "receiver.h"  // Include the receiver header
#include <daemon.h>  // Include daemon-related functions
#include <network/socket.h>  // Include socket functions
#include <processing/jobs/job.h>  // Include job functions
#include <processing/jobs/process_message_job.h>  // Include process message job functions
#include <processing/jobs/callback_job.h>  // Include callback job functions
#include <crypto/hashers/hasher.h>  // Include hasher functions
#include <threading/mutex.h>  // Include mutex functions
#include <networking/packet.h>  // Include packet functions
/** lifetime of a cookie, in seconds */
#define COOKIE_LIFETIME 10
/** time we wait before disabling cookies */
#define COOKIE_CALMDOWN_DELAY 10
/** number of per-IP timestamps we keep track of (must be a power of 2) */
#define COOKIE_CALMDOWN_BUCKETS 32
/** mask applied to IP address hashes to determine the timestamp index */
#define COOKIE_CALMDOWN_MASK (COOKIE_CALMDOWN_BUCKETS-1)
/** time in seconds we use a secret at most (since we keep two secrets, must
 * be at least COOKIE_LIFETIME to process all outstanding valid cookies)  */
#define COOKIE_SECRET_SWITCH 120
/** default value for private_receiver_t.cookie_threshold */
#define COOKIE_THRESHOLD_DEFAULT 30
/** default value for private_receiver_t.cookie_threshold_ip (must be lower
 * than BLOCK_THRESHOLD_DEFAULT) */
#define COOKIE_THRESHOLD_IP_DEFAULT 3
/** default value for private_receiver_t.block_threshold */
#define BLOCK_THRESHOLD_DEFAULT 5
/** length of the secret to use for cookie calculation */
#define SECRET_LENGTH 16
/** Length of a notify payload header */
#define NOTIFY_PAYLOAD_HEADER_LENGTH 8
// Define a type for the private receiver structure
typedef struct private_receiver_t private_receiver_t;
/**
 * Private data of a receiver_t object.
 */
struct private_receiver_t {
	/**
	 * Public part of a receiver_t object.
	 */
	receiver_t public;
	/**
	 * Registered callback for ESP packets
	 */
	struct {
		receiver_esp_cb_t cb;  // Callback function for ESP packets
		void *data;  // Data provided to the callback
	} esp_cb;
	/**
	 * Mutex for ESP callback
	 */
	mutex_t *esp_cb_mutex;  // Mutex to synchronize access to the ESP callback
	/**
	 * current secret to use for cookie calculation
	 */
	char secret[SECRET_LENGTH];  // Current secret for cookie calculation
	/**
	 * previous secret used to verify older cookies
	 */
	char secret_old[SECRET_LENGTH];  // Previous secret to verify older cookies
	/**
	 * time we used the current secret first
	 */
	uint32_t secret_first_use;  // Time when the current secret was first used
	/**
	 * time offset to use, hides our system time
	 */
	uint32_t secret_offset;  // Time offset to hide the system time
	/**
	 * the RNG to use for secret generation
	 */
	rng_t *rng;  // Random number generator for secret generation
	/**
	 * hasher to use for cookie calculation
	 */
	hasher_t *hasher;  // Hasher for cookie calculation
	/**
	 * require cookies after this many half open IKE_SAs
	 */
	u_int cookie_threshold;  // Threshold for requiring cookies
	/**
	 * require cookies for a specific IP after this many half open IKE_SAs
	 */
	u_int cookie_threshold_ip;  // Threshold for requiring cookies for a specific IP
	/**
	 * global (0) and per-IP hash (1..n) timestamps of when the threshold was
	 * last reached
	 */
	time_t last_threshold[COOKIE_CALMDOWN_BUCKETS+1];  // Timestamps of when the threshold was last reached
	/**
	 * how many half open IKE_SAs per peer before blocking
	 */
	u_int block_threshold;  // Threshold for blocking half open IKE_SAs per peer
	/**
	 * Drop IKE_SA_INIT requests if processor job load exceeds this limit
	 */
	u_int init_limit_job_load;  // Limit for dropping IKE_SA_INIT requests based on job load
	/**
	 * Drop IKE_SA_INIT requests if half open IKE_SA count exceeds this limit
	 */
	u_int init_limit_half_open;  // Limit for dropping IKE_SA_INIT requests based on half open IKE_SA count
	/**
	 * Delay for receiving incoming packets, to simulate larger RTT
	 */
	int receive_delay;  // Delay for receiving incoming packets
	/**
	 * Specific message type to delay, 0 for any
	 */
	int receive_delay_type;  // Specific message type to delay
	/**
	 * Delay request messages?
	 */
	bool receive_delay_request;  // Flag to indicate if request messages should be delayed
	/**
	 * Delay response messages?
	 */
	bool receive_delay_response;  // Flag to indicate if response messages should be delayed
	/**
	 * Endpoint is allowed to act as an initiator only
	 */
	bool initiator_only;  // Flag to indicate if the endpoint can act as an initiator only
};
/**
 * send a notify back to the sender
 */
static void send_notify(message_t *request, int major, exchange_type_t exchange, notify_type_t type, chunk_t data) {
	// Declare pointers for the IKE SA ID, response message, source host, destination host, and packet
	ike_sa_id_t *ike_sa_id;
	message_t *response;
	host_t *src, *dst;
	packet_t *packet;
	// Create a response message with the specified major version
	response = message_create(major, 0);
	// Set the exchange type for the response message
	response->set_exchange_type(response, exchange);
	// Add a notify payload to the response message
	response->add_notify(response, FALSE, type, data);
	// Get the source and destination hosts from the request message
	dst = request->get_source(request);
	src = request->get_destination(request);
	// Set the source and destination for the response message
	response->set_source(response, src->clone(src));
	response->set_destination(response, dst->clone(dst));
	// If the major version is IKEv2
	if (major == IKEV2_MAJOR_VERSION) {
		// Set the response flag and message ID for the response message
		response->set_request(response, FALSE);
		response->set_message_id(response, request->get_message_id(request));
	}
	// Get the IKE SA ID from the request message and switch the initiator flag
	ike_sa_id = request->get_ike_sa_id(request);
	ike_sa_id->switch_initiator(ike_sa_id);
	// Set the IKE SA ID for the response message
	response->set_ike_sa_id(response, ike_sa_id);
	// Generate the response message and create a packet
	if (response->generate(response, NULL, &packet) == SUCCESS) {
		// Send the packet using the charon sender
		charon->sender->send(charon->sender, packet);
	}
	// Destroy the response message
	response->destroy(response);
}
/**
 * build a cookie
 */
static bool cookie_build(private_receiver_t *this, message_t *message, uint32_t t, chunk_t secret, chunk_t *cookie) {
	// Declare variables for the SPI, source IP address, input chunk, and hash chunk
	uint64_t spi = message->get_initiator_spi(message);
	host_t *ip = message->get_source(message);
	chunk_t input, hash;
	/* COOKIE = t | sha1( IPi | SPIi | t | secret ) */
	// Concatenate the IP address, SPI, timestamp, and secret into the input chunk
	input = chunk_cata("cccc", ip->get_address(ip), chunk_from_thing(spi), chunk_from_thing(t), secret);
	// Allocate memory for the hash
	hash = chunk_alloca(this->hasher->get_hash_size(this->hasher));
	// Calculate the hash of the input chunk
	if (!this->hasher->get_hash(this->hasher, input, hash.ptr)) {
		return FALSE;
	}
	// Concatenate the timestamp and hash into the cookie
	*cookie = chunk_cat("cc", chunk_from_thing(t), hash);
	return TRUE;
}
/**
 * verify a received cookie
 */
static bool cookie_verify(private_receiver_t *this, message_t *message, chunk_t cookie) {
	// Declare variables for the timestamp and current time
	uint32_t t, now;
	// Declare variables for the reference and secret chunks
	chunk_t reference;
	chunk_t secret;
	// Get the current monotonic time
	now = time_monotonic(NULL);
	// Extract the timestamp from the cookie
	t = *(uint32_t*)cookie.ptr;
	// Check if the cookie length is valid and the cookie has not expired
	if (cookie.len != sizeof(uint32_t) + this->hasher->get_hash_size(this->hasher) || t < now - this->secret_offset - COOKIE_LIFETIME) {
		// Log a debug message indicating the cookie has expired
		DBG2(DBG_NET, "received cookie lifetime expired, rejecting");
		// Return FALSE to indicate invalid cookie
		return FALSE;
	}
	/* check if cookie is derived from old_secret */
	// Check if the cookie was generated with the current secret
	if (t + this->secret_offset >= this->secret_first_use) {
		secret = chunk_from_thing(this->secret);
	} else {
		// Use the old secret to verify the cookie
		secret = chunk_from_thing(this->secret_old);
	}
	/* compare own calculation against received */
	// Build the reference cookie using the message and secret
	if (!cookie_build(this, message, t, secret, &reference)) {
		// Return FALSE if cookie building failed
		return FALSE;
	}
	// Compare the reference cookie with the received cookie
	if (chunk_equals_const(reference, cookie)) {
		// Free the reference chunk and return TRUE if cookies match
		chunk_free(&reference);
		return TRUE;
	}
	// Free the reference chunk and return FALSE if cookies do not match
	chunk_free(&reference);
	return FALSE;
}

/**
 * Check if a valid cookie found
 */
static bool check_cookie(private_receiver_t *this, message_t *message) {
	// Declare a chunk for the cookie data
	chunk_t data;
	/* check for a cookie. We don't use our parser here and do it
	 * quick and dirty for performance reasons.
	 * we assume the cookie is the first payload (which is a MUST), and
	 * the cookie's SPI length is zero. */
	// Get the packet data from the message
	data = message->get_packet_data(message);
	// Check if the data length is sufficient and the notify payload type is COOKIE
	if (data.len < IKE_HEADER_LENGTH + NOTIFY_PAYLOAD_HEADER_LENGTH + sizeof(uint32_t) + this->hasher->get_hash_size(this->hasher) ||	*(data.ptr + 16) != PLV2_NOTIFY || *(uint16_t*)(data.ptr + IKE_HEADER_LENGTH + 6) != htons(COOKIE)) {
		// Return FALSE if no valid cookie is found
		return FALSE;
	}
	// Adjust the data pointer to point to the cookie value
	data.ptr += IKE_HEADER_LENGTH + NOTIFY_PAYLOAD_HEADER_LENGTH;
	data.len = sizeof(uint32_t) + this->hasher->get_hash_size(this->hasher);
	// Verify the cookie
	if (!cookie_verify(this, message, data)) {
		// Log a debug message indicating the cookie is invalid
		DBG2(DBG_NET, "found cookie, but content invalid");
		// Return FALSE if cookie verification failed
		return FALSE;
	}
	// Return TRUE if a valid cookie is found
	return TRUE;
}
/**
 * Struct to keep track of half-open SA counts
 */
typedef struct {
	u_int count;  // Count of half-open SAs
	bool determined;  // Flag to indicate if the count is determined
} half_open_count_t;
/**
 * Get the number of half-open SAs, cached or from the manager, either global
 * or for a single IP.
 */
static u_int get_half_open_count(half_open_count_t *this, host_t *src) {
	// Check if the count is not determined
	if (!this->determined) {
		// Set the determined flag to TRUE
		this->determined = TRUE;
		// Get the half-open SA count from the IKE SA manager
		this->count = charon->ike_sa_manager->get_half_open_count(charon->ike_sa_manager, src, TRUE);
	}
	// Return the half-open SA count
	return this->count;
}
/**
 * Check if we currently require cookies either globally or for the given IP
 */
static bool cookie_required(private_receiver_t *this, half_open_count_t *half_open, host_t *src, uint32_t now) {
	// Declare a variable for the threshold
	u_int threshold = src ? this->cookie_threshold_ip : this->cookie_threshold;
	// Declare a variable for the timestamp index
	u_int idx = 0;
	// Return FALSE if the threshold is zero
	if (!threshold)	{
		return FALSE;
	}
	// Check if the source IP is provided
	if (src) {
		/* keep track of IPs in segments so not all are affected if a single
		 * IP is targeted */
		// Calculate the timestamp index based on the IP address hash
		idx = 1 + (chunk_hash(src->get_address(src)) & COOKIE_CALMDOWN_MASK);
	}
	// Check if the half-open SA count exceeds the threshold
	if (get_half_open_count(half_open, src) >= threshold) {
		// Update the last threshold timestamp and return TRUE
		this->last_threshold[idx] = now;
		return TRUE;
	}
	// Check if the last threshold timestamp is within the calm-down delay
	if (this->last_threshold[idx] && now < this->last_threshold[idx] + COOKIE_CALMDOWN_DELAY) {
		/* We don't disable cookies unless the threshold was not reached for
		 * COOKIE_CALMDOWN_DELAY seconds. This avoids jittering between
		 * cookie on / cookie off states, which is problematic. Consider the
		 * following: A legitimate initiator sends an IKE_SA_INIT while we
		 * are under a DoS attack. If we toggle our cookie behavior,
		 * multiple retransmits of this IKE_SA_INIT might get answered with
		 * and without cookies. The initiator goes on and retries with
		 * a cookie, but it can't know if the completing IKE_SA_INIT response
		 * is to its IKE_SA_INIT request with or without cookies. This is
		 * problematic, as the cookie is part of the AUTH payload data.
		 */
		// Return TRUE if the calm-down delay has not passed
		return TRUE;
	}
	// Return FALSE if cookies are not required
	return FALSE;
}
/**
 * Check if we should drop IKE_SA_INIT because of cookie/overload checking
 */
static bool drop_ike_sa_init(private_receiver_t *this, message_t *message) {
	// Declare variables for half-open SA counts and source host
	half_open_count_t half_open = {}, half_open_ip = {};
	host_t *src;
	// Declare a variable for the current time
	uint32_t now;
	// Get the source host from the message
	src = message->get_source(message);
	// Get the current monotonic time
	now = time_monotonic(NULL);
	/* check for cookies in IKEv2 */
	// Check if the message is IKEv2 and requires cookies
	if (message->get_major_version(message) == IKEV2_MAJOR_VERSION && (cookie_required(this, &half_open, NULL, now) ||  cookie_required(this, &half_open_ip, src, now)) && !check_cookie(this, message)) {
		// Declare a chunk for the cookie
		chunk_t cookie;
		// Log a debug message indicating the received packet
		DBG2(DBG_NET, "received packet: from %#H to %#H (%zu bytes)", src, message->get_destination(message), message->get_packet_data(message).len);
		// Check if the secret first use time is not set
		if (!this->secret_first_use) {
			// Set the secret first use time to the current time
			this->secret_first_use = now;
		}
		else if (now - this->secret_first_use > COOKIE_SECRET_SWITCH) {
			// Declare a buffer for the new secret
			char secret[SECRET_LENGTH];
			// Log a debug message indicating generating a new cookie secret
			DBG1(DBG_NET, "generating new cookie secret after %ds since first " "use", now - this->secret_first_use);
			// Generate a new secret using the RNG
			if (this->rng->get_bytes(this->rng, SECRET_LENGTH, secret)) {
				// Copy the old secret to the secret_old buffer
				memcpy(this->secret_old, this->secret, SECRET_LENGTH);
				// Copy the new secret to the secret buffer
				memcpy(this->secret, secret, SECRET_LENGTH);
				// Wipe the new secret buffer
				memwipe(secret, SECRET_LENGTH);
				// Set the secret first use time to the current time
				this->secret_first_use = now;
			} else {
				// Log a debug message indicating failed to allocate cookie secret
				DBG1(DBG_NET, "failed to allocated cookie secret, keeping old");
			}
		}
		// Build a cookie using the current time and secret
		if (!cookie_build(this, message, now - this->secret_offset,chunk_from_thing(this->secret), &cookie)) {
			// Return TRUE if cookie building failed
			return TRUE;
		}
		// Log a debug message indicating sending COOKIE notify
		DBG2(DBG_NET, "sending COOKIE notify to %H", src);
		// Send a COOKIE notify back to the sender
		send_notify(message, IKEV2_MAJOR_VERSION, IKE_SA_INIT, COOKIE, cookie);
		// Free the cookie chunk
		chunk_free(&cookie);
		// Return TRUE to drop the IKE_SA_INIT
		return TRUE;
	}
	/* check if peer has too many IKE_SAs half open */
	// Check if the peer has exceeded the per-IP half-open IKE_SA limit
	if (this->block_threshold && get_half_open_count(&half_open_ip, src) >= this->block_threshold) {
		// Log a debug message indicating the per-IP half-open IKE_SA limit is reached
		DBG1(DBG_NET, "ignoring IKE_SA setup from %H, per-IP half-open IKE_SA " "limit of %d reached", src, this->block_threshold);
		// Return TRUE to drop the IKE_SA_INIT
		return TRUE;
	}
	/* check if global half open IKE_SA limit reached */
	// Check if the global half-open IKE_SA limit is reached
	if (this->init_limit_half_open && get_half_open_count(&half_open, NULL) >= this->init_limit_half_open) {
		// Log a debug message indicating the global half-open IKE_SA limit is reached
		DBG1(DBG_NET, "ignoring IKE_SA setup from %H, half-open IKE_SA " "limit of %d reached", src, this->init_limit_half_open);
		// Return TRUE to drop the IKE_SA_INIT
		return TRUE;
	}
	/* check if job load acceptable */
	// Check if the job load is within acceptable limits
	if (this->init_limit_job_load) {
		// Declare variables for job counts and priority levels
		u_int jobs = 0, i;
		// Iterate through all priority levels and get the job load
		for (i = 0; i < JOB_PRIO_MAX; i++) {
			jobs += lib->processor->get_job_load(lib->processor, i);
		}
		// Check if the job load exceeds the limit
		if (jobs > this->init_limit_job_load) {
			// Log a debug message indicating the job load exceeds the limit
			DBG1(DBG_NET, "ignoring IKE_SA setup from %H, job load of %d " "exceeds limit of %d", src, jobs, this->init_limit_job_load);
			// Return TRUE to drop the IKE_SA_INIT
			return TRUE;
		}
	}
	// Return FALSE if IKE_SA_INIT should not be dropped
	return FALSE;
}
/**
 * Job callback to receive packets
 */
static job_requeue_t receive_packets(private_receiver_t *this) {
	// Declare pointers for IKE SA ID, packet, message, source host, and destination host
	ike_sa_id_t *id;
	packet_t *packet;
	message_t *message;
	host_t *src, *dst;
	// Declare a variable for the status
	status_t status;
	// Declare a boolean for supported status
	bool supported = TRUE;
	// Declare chunks for data and Non-ESP marker
	chunk_t data, marker = chunk_from_chars(0x00, 0x00, 0x00, 0x00);
	/* read in a packet */
	// Receive a packet from the charon socket
	status = charon->socket->receive(charon->socket, &packet);
	// Check if receiving is not supported
	if (status == NOT_SUPPORTED) {
		// Return JOB_REQUEUE_NONE to indicate no requeueing
		return JOB_REQUEUE_NONE;
	}
	if (status != SUCCESS || !packet)	{
		// Log a debug message indicating receiving from socket failed
		DBG2(DBG_NET, "receiving from socket failed!");
		// Return JOB_REQUEUE_FAIR to indicate fair requeueing
		return JOB_REQUEUE_FAIR;
	}
	// Get the packet data
	data = packet->get_data(packet);
	// Check if the packet is a NAT-T keepalive
	if (data.len == 1 && data.ptr[0] == 0xFF) {
		/* silently drop NAT-T keepalives */
		// Destroy the packet and return JOB_REQUEUE_DIRECT
		packet->destroy(packet);
		return JOB_REQUEUE_DIRECT;
	} else if (data.len < marker.len) {
		/* drop packets that are too small */
		// Log a debug message indicating the packet is too short
		DBG3(DBG_NET, "received packet is too short (%d bytes)", data.len);
		// Destroy the packet and return JOB_REQUEUE_DIRECT
		packet->destroy(packet);
		return JOB_REQUEUE_DIRECT;
	}
	// Get the source and destination hosts from the packet
	dst = packet->get_destination(packet);
	src = packet->get_source(packet);
	// Check if all interfaces are not usable and the destination interface is ignored
	if (!charon->kernel->all_interfaces_usable(charon->kernel) && !charon->kernel->get_interface(charon->kernel, dst, NULL)) {
		// Log a debug message indicating the packet is received on an ignored interface
		DBG3(DBG_NET, "received packet from %#H to %#H on ignored interface", src, dst);
		// Destroy the packet and return JOB_REQUEUE_DIRECT
		packet->destroy(packet);
		return JOB_REQUEUE_DIRECT;
	}
	/* if neither source nor destination port is 500 we assume an IKE packet
	 * with Non-ESP marker or an ESP packet */
	// Check if neither source nor destination port is 500
	if (dst->get_port(dst) != IKEV2_UDP_PORT &&	src->get_port(src) != IKEV2_UDP_PORT) {
		// Check if the packet starts with a Non-ESP marker
		if (memeq(data.ptr, marker.ptr, marker.len)) {
			/* remove Non-ESP marker */
			// Skip the Non-ESP marker bytes in the packet
			packet->skip_bytes(packet, marker.len);
		} else {
			/* this seems to be an ESP packet */
			// Lock the ESP callback mutex
			this->esp_cb_mutex->lock(this->esp_cb_mutex);
			// Check if the ESP callback is registered
			if (this->esp_cb.cb) {
				// Call the ESP callback with the packet
				this->esp_cb.cb(this->esp_cb.data, packet);
			} else {
				// Destroy the packet if no ESP callback is registered
				packet->destroy(packet);
			}
			// Unlock the ESP callback mutex
			this->esp_cb_mutex->unlock(this->esp_cb_mutex);
			// Return JOB_REQUEUE_DIRECT to indicate direct requeueing
			return JOB_REQUEUE_DIRECT;
		}
	}
	/* parse message header */
	// Create a message from the packet
	message = message_create_from_packet(packet);
	// Parse the message header
	if (message->parse_header(message) != SUCCESS) {
		// Log a debug message indicating invalid IKE header
		DBG1(DBG_NET, "received invalid IKE header from %H - ignored", src);
		// Alert the bus about the parse error
		charon->bus->alert(charon->bus, ALERT_PARSE_ERROR_HEADER, message);
		// Destroy the message and return JOB_REQUEUE_DIRECT
		message->destroy(message);
		return JOB_REQUEUE_DIRECT;
	}
	/* check IKE major version */
	switch (message->get_major_version(message)) {
		case IKEV2_MAJOR_VERSION:
			#ifndef USE_IKEV2
				// If IKEv2 is not used, send INVALID_MAJOR_VERSION notify for IKE_SA_INIT requests
				if (message->get_exchange_type(message) == IKE_SA_INIT &&
					message->get_request(message))
				{
					send_notify(message, IKEV1_MAJOR_VERSION, INFORMATIONAL_V1,
								INVALID_MAJOR_VERSION, chunk_empty);
					supported = FALSE;
				}
			#endif /* USE_IKEV2 */
		break;
		case IKEV1_MAJOR_VERSION:
			#ifndef USE_IKEV1
			// If IKEv1 is not used, send INVALID_MAJOR_VERSION notify for ID_PROT or AGGRESSIVE exchanges
			if (message->get_exchange_type(message) == ID_PROT || message->get_exchange_type(message) == AGGRESSIVE) {
				send_notify(message, IKEV2_MAJOR_VERSION, INFORMATIONAL, INVALID_MAJOR_VERSION, chunk_empty);
				supported = FALSE;
			}
			#endif /* USE_IKEV1 */
		break;
		default:
			#ifdef USE_IKEV2
				// Send INVALID_MAJOR_VERSION notify for unsupported IKE versions if IKEv2 is used
				send_notify(message, IKEV2_MAJOR_VERSION, message->get_exchange_type(message),INVALID_MAJOR_VERSION, chunk_empty);
			#elif defined(USE_IKEV1)
				// Send INVALID_MAJOR_VERSION notify for unsupported IKE versions if IKEv1 is used
				send_notify(message, IKEV1_MAJOR_VERSION, INFORMATIONAL_V1, INVALID_MAJOR_VERSION, chunk_empty);
			#endif /* USE_IKEV1 */
				supported = FALSE;
		break;
	}
	if (!supported)	{
		// Log a debug message indicating unsupported IKE version
		DBG1(DBG_NET, "received unsupported IKE version %d.%d from %H, sending " "INVALID_MAJOR_VERSION", message->get_major_version(message), message->get_minor_version(message), src);
		// Destroy the message and return JOB_REQUEUE_DIRECT
		message->destroy(message);
		return JOB_REQUEUE_DIRECT;
	}
	if (message->get_request(message) && message->get_exchange_type(message) == IKE_SA_INIT)	{
		// Get the IKE SA ID from the message
		id = message->get_ike_sa_id(message);
		// Check if the initiator only flag is set or the message is from a responder
		if (this->initiator_only || !id->is_initiator(id) || drop_ike_sa_init(this, message)) {
			// Destroy the message and return JOB_REQUEUE_DIRECT
			message->destroy(message);
			return JOB_REQUEUE_DIRECT;
		}
	}
	if (message->get_exchange_type(message) == ID_PROT || message->get_exchange_type(message) == AGGRESSIVE) {
		// Get the IKE SA ID from the message
		id = message->get_ike_sa_id(message);
		// Check if the responder SPI is zero and the initiator only flag is set or the IKE_SA_INIT should be dropped
		if (id->get_responder_spi(id) == 0 && (this->initiator_only || drop_ike_sa_init(this, message))) {
			// Destroy the message and return JOB_REQUEUE_DIRECT
			message->destroy(message);
			return JOB_REQUEUE_DIRECT;
		}
	}
	// Check if a receive delay is configured
	if (this->receive_delay) {
		// Check if the receive delay type matches the message exchange type
		if (this->receive_delay_type == 0 || this->receive_delay_type == message->get_exchange_type(message)) {
			// Check if the message is a request or response and apply delay if needed
			if ((message->get_request(message) && this->receive_delay_request) || (!message->get_request(message) && this->receive_delay_response)) {
				// Log a debug message indicating the receive delay
				DBG1(DBG_NET, "using receive delay: %dms", this->receive_delay);
				// Schedule a job to process the message after the receive delay
				lib->scheduler->schedule_job_ms(lib->scheduler,	(job_t*)process_message_job_create(message), this->receive_delay);
				// Return JOB_REQUEUE_DIRECT to indicate direct requeueing
				return JOB_REQUEUE_DIRECT;
			}
		}
	}
	// Queue a job to process the message
	lib->processor->queue_job(lib->processor, (job_t*)process_message_job_create(message));
	// Return JOB_REQUEUE_DIRECT to indicate direct requeueing
	return JOB_REQUEUE_DIRECT;
}
// Method to add an ESP callback
METHOD(receiver_t, add_esp_cb, void, private_receiver_t *this, receiver_esp_cb_t callback, void *data) {
	// Lock the mutex to synchronize access to the ESP callback
	this->esp_cb_mutex->lock(this->esp_cb_mutex);
	// Set the ESP callback and associated data
	this->esp_cb.cb = callback;
	this->esp_cb.data = data;
	// Unlock the mutex
	this->esp_cb_mutex->unlock(this->esp_cb_mutex);
}
// Method to delete an ESP callback
METHOD(receiver_t, del_esp_cb, void, private_receiver_t *this, receiver_esp_cb_t callback) {
	// Lock the mutex to synchronize access to the ESP callback
	this->esp_cb_mutex->lock(this->esp_cb_mutex);
	// Check if the current ESP callback matches the callback to delete
	if (this->esp_cb.cb == callback) {
		// Set the ESP callback and associated data to NULL
		this->esp_cb.cb = NULL;
		this->esp_cb.data = NULL;
	}
	// Unlock the mutex
	this->esp_cb_mutex->unlock(this->esp_cb_mutex);
}
// Method to destroy the receiver object
METHOD(receiver_t, destroy, void, private_receiver_t *this) {
	// Destroy the RNG object
	this->rng->destroy(this->rng);
	// Destroy the hasher object
	this->hasher->destroy(this->hasher);
	// Destroy the ESP callback mutex
	this->esp_cb_mutex->destroy(this->esp_cb_mutex);
	// Free the private receiver structure
	free(this);
}
/*
 * Described in header.
 */
// Function to create a receiver object
receiver_t *receiver_create() {
	// Declare a pointer for the private receiver structure
	private_receiver_t *this;
	// Get the current monotonic time
	uint32_t now = time_monotonic(NULL);
	// Initialize the private receiver structure
	INIT(this,
		.public = {
			.add_esp_cb = _add_esp_cb,  // Set the add_esp_cb method
			.del_esp_cb = _del_esp_cb,  // Set the del_esp_cb method
			.destroy = _destroy,  // Set the destroy method
		},
		.esp_cb_mutex = mutex_create(MUTEX_TYPE_DEFAULT),  // Create a mutex for the ESP callback
		.secret_offset = now ? random() % now : 0,  // Initialize the secret offset with a random value
	);
	// Check if DoS protection is enabled in the settings
	if (lib->settings->get_bool(lib->settings,"%s.dos_protection", TRUE, lib->ns)) {
		// Get the cookie threshold from the settings
		this->cookie_threshold = lib->settings->get_int(lib->settings,"%s.cookie_threshold", COOKIE_THRESHOLD_DEFAULT, lib->ns);
		// Get the per-IP cookie threshold from the settings
		this->cookie_threshold_ip = lib->settings->get_int(lib->settings,"%s.cookie_threshold_ip", COOKIE_THRESHOLD_IP_DEFAULT, lib->ns);
		// Get the block threshold from the settings
		this->block_threshold = lib->settings->get_int(lib->settings,"%s.block_threshold", BLOCK_THRESHOLD_DEFAULT, lib->ns);
		// Ensure the block threshold is higher than the per-IP cookie threshold
		if (this->cookie_threshold_ip >= this->block_threshold) {
			this->block_threshold = this->cookie_threshold_ip + 1;
			// Log a debug message indicating the adjusted block threshold
			DBG1(DBG_NET, "increasing block threshold to %u due to per-IP "
				 "cookie threshold of %u", this->block_threshold,
				 this->cookie_threshold_ip);
		}
	}
	// Get various limits and delay configurations from the settings
	this->init_limit_job_load = lib->settings->get_int(lib->settings,"%s.init_limit_job_load", 0, lib->ns);
	this->init_limit_half_open = lib->settings->get_int(lib->settings,"%s.init_limit_half_open", 0, lib->ns);
	this->receive_delay = lib->settings->get_int(lib->settings,"%s.receive_delay", 0, lib->ns);
	this->receive_delay_type = lib->settings->get_int(lib->settings,"%s.receive_delay_type", 0, lib->ns);
	this->receive_delay_request = lib->settings->get_bool(lib->settings,"%s.receive_delay_request", TRUE, lib->ns);
	this->receive_delay_response = lib->settings->get_bool(lib->settings,"%s.receive_delay_response", TRUE, lib->ns);
	this->initiator_only = lib->settings->get_bool(lib->settings,"%s.initiator_only", FALSE, lib->ns);
	// Create a hasher for cookie calculation
	this->hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!this->hasher) {
		// Log a debug message if creating the hasher failed
		DBG1(DBG_NET, "creating cookie hasher failed, no hashers supported");
		// Free the private receiver structure and return NULL
		free(this);
		return NULL;
	}
	// Create an RNG for secret generation
	this->rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!this->rng) {
		// Log a debug message if creating the RNG failed
		DBG1(DBG_NET, "creating cookie RNG failed, no RNG supported");
		// Destroy the hasher and free the private receiver structure
		this->hasher->destroy(this->hasher);
		free(this);
		return NULL;
	}
	// Generate the initial secret using the RNG
	if (!this->rng->get_bytes(this->rng, SECRET_LENGTH, this->secret)) {
		// Log a debug message if generating the secret failed
		DBG1(DBG_NET, "creating cookie secret failed");
		// Destroy the receiver object and return NULL
		destroy(this);
		return NULL;
	}
	// Copy the initial secret to the old secret buffer
	memcpy(this->secret_old, this->secret, SECRET_LENGTH);
	// Queue the receive_packets job with critical priority
	lib->processor->queue_job(lib->processor, (job_t*)callback_job_create_with_prio((callback_job_cb_t)receive_packets, this, NULL, (callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));
	// Return the public part of the receiver structure
	return &this->public;
}