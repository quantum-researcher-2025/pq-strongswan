/*
 * Copyright (C) 2006-2013 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005-2010 Martin Willi
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

/* for struct in6_pktinfo */
#define _GNU_SOURCE  // Define _GNU_SOURCE to ensure GNU extensions are included
#include "socket_dynamic_socket.h"  // Include the header file for the socket dynamic socket
#include <sys/types.h>  // Include system types
#include <sys/socket.h>  // Include socket definitions
#include <string.h>  // Include string manipulation functions
#include <errno.h>  // Include error number definitions
#include <unistd.h>  // Include standard symbolic constants and types
#include <stdlib.h>  // Include standard library functions
#include <fcntl.h>  // Include file control options
#include <sys/ioctl.h>  // Include IO control operations
#include <netinet/in_systm.h>  // Include internet system definitions
#include <netinet/in.h>  // Include internet address family definitions
#include <netinet/ip.h>  // Include IP header definitions
#include <netinet/udp.h>  // Include UDP header definitions
#include <net/if.h>  // Include network interface definitions
#include <daemon.h>  // Include daemon-related functions
#include <threading/thread.h>  // Include threading functions
#include <threading/rwlock.h>  // Include read-write lock functions
#include <collections/hashtable.h>  // Include hashtable functions
/* these are not defined on some platforms */
#ifndef SOL_IP
	#define SOL_IP IPPROTO_IP  // Define SOL_IP if not already defined
#endif
#ifndef SOL_IPV6
	#define SOL_IPV6 IPPROTO_IPV6  // Define SOL_IPV6 if not already defined
#endif
/* IPV6_RECVPKTINFO is defined in RFC 3542 which obsoletes RFC 2292 that
 * previously defined IPV6_PKTINFO */
#ifndef IPV6_RECVPKTINFO
	#define IPV6_RECVPKTINFO IPV6_PKTINFO  // Define IPV6_RECVPKTINFO if not already defined
#endif
// Define a type for the private socket dynamic socket structure
typedef struct private_socket_dynamic_socket_t private_socket_dynamic_socket_t;
// Define a type for the dynamic socket structure
typedef struct dynsock_t dynsock_t;
/**
 * Private data of a socket_t object
 */
struct private_socket_dynamic_socket_t {
	/**
	 * public functions
	 */
	socket_dynamic_socket_t public;  // The public part of the structure, implementing the socket interface
	/**
	 * Hashtable of bound sockets
	 */
	hashtable_t *sockets;  // A hashtable to store bound sockets
	/**
	 * Lock for sockets hashtable
	 */
	rwlock_t *lock;  // A read-write lock for synchronizing access to the hashtable
	/**
	 * Notification pipe to signal receiver
	 */
	int notify[2];  // An array to store file descriptors for a notification pipe
	/**
	 * Maximum packet size to receive
	 */
	int max_packet;  // The maximum size of packets that can be received
};
/**
 * Struct for a dynamically allocated socket
 */
struct dynsock_t {
	/**
	 * File descriptor of socket
	 */
	int fd;  // The file descriptor for the socket
	/**
	 * Address family
	 */
	int family;  // The address family (e.g., AF_INET for IPv4, AF_INET6 for IPv6)
	/**
	 * Bound source port
	 */
	uint16_t port;  // The port number to which the socket is bound
};
/**
 * Hash function for hashtable
 */
static u_int hash(dynsock_t *key) {
	// Return a hash value combining the family and port
	return (key->family << 16) | key->port;
}
/**
 * Equals function for hashtable
 */
static bool equals(dynsock_t *a, dynsock_t *b) {
	// Return true if both the family and port of the two keys are equal
	return a->family == b->family && a->port == b->port;
}
/**
 * Create a fd_set from all bound sockets
 */
static int build_fds(private_socket_dynamic_socket_t *this, fd_set *fds) {
	// Declare a pointer for the enumerator
	enumerator_t *enumerator;
	// Declare pointers for the key and value in the hashtable
	dynsock_t *key, *value;
	// Declare an integer to keep track of the maximum file descriptor
	int maxfd;
	// Clear the fd_set
	FD_ZERO(fds);
	// Add the notification pipe's read end to the fd_set
	FD_SET(this->notify[0], fds);
	// Set the initial maxfd to the notification pipe's read end
	maxfd = this->notify[0];
	// Acquire a read lock on the sockets hashtable
	this->lock->read_lock(this->lock);
	// Create an enumerator for the sockets hashtable
	enumerator = this->sockets->create_enumerator(this->sockets);
	// Enumerate through all the key-value pairs in the hashtable
	while (enumerator->enumerate(enumerator, &key, &value)) {
		// Add the socket's file descriptor to the fd_set
		FD_SET(value->fd, fds);
		// Update maxfd to be the maximum of the current maxfd and the socket's file descriptor
		maxfd = max(maxfd, value->fd);
	}
	// Destroy the enumerator
	enumerator->destroy(enumerator);
	// Release the read lock on the sockets hashtable
	this->lock->unlock(this->lock);
	// Return the maximum file descriptor plus one
	return maxfd + 1;
}
/**
 * Find the socket select()ed
 */
static dynsock_t* scan_fds(private_socket_dynamic_socket_t *this, fd_set *fds) {
	// Declare a pointer for the enumerator
	enumerator_t *enumerator;
	// Declare pointers for the key, value, and the selected socket
	dynsock_t *key, *value, *selected = NULL;
	// Acquire a read lock on the sockets hashtable
	this->lock->read_lock(this->lock);
	// Create an enumerator for the sockets hashtable
	enumerator = this->sockets->create_enumerator(this->sockets);
	// Enumerate through all the key-value pairs in the hashtable
	while (enumerator->enumerate(enumerator, &key, &value))	{
		// Check if the file descriptor is set in the fd_set
		if (FD_ISSET(value->fd, fds)) {
			// Set the selected socket to the current value
			selected = value;
			// Break the loop as we found the selected socket
			break;
		}
	}
	// Destroy the enumerator
	enumerator->destroy(enumerator);
	// Release the read lock on the sockets hashtable
	this->lock->unlock(this->lock);
	// Return the selected socket
	return selected;
}
/**
 * Receive a packet from a given socket fd
 */
static packet_t *receive_packet(private_socket_dynamic_socket_t *this, dynsock_t *skt) {
	// Declare pointers for source and destination hosts
	host_t *source = NULL, *dest = NULL;
	// Declare a variable for the length of received data
	ssize_t len;
	// Declare a buffer to store received data
	char buffer[this->max_packet];
	// Declare a chunk to hold data
	chunk_t data;
	// Declare a pointer for the packet
	packet_t *packet;
	// Declare structures for message header and control message header
	struct msghdr msg;
	struct cmsghdr *cmsgptr;
	// Declare an IO vector structure
	struct iovec iov;
	// Declare a buffer for ancillary data
	char ancillary[64];
	// Declare a union for source address
	union {
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	} src;
	// Initialize the message header structure
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	iov.iov_base = buffer;
	iov.iov_len = this->max_packet;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ancillary;
	msg.msg_controllen = sizeof(ancillary);
	msg.msg_flags = 0;
	// Receive a message from the socket
	len = recvmsg(skt->fd, &msg, 0);
	// Check if receiving the message failed
	if (len < 0) {
		// Log an error message if reading the socket failed
		DBG1(DBG_NET, "error reading socket: %s", strerror(errno));
		return NULL;
	}
	// Check if the message was truncated
	if (msg.msg_flags & MSG_TRUNC) {
		// Log a message if the receive buffer is too small
		DBG1(DBG_NET, "receive buffer too small, packet discarded");
		return NULL;
	}
	// Log the received packet
	DBG3(DBG_NET, "received packet %b", buffer, (u_int)len);
	/* read ancillary data to get destination address */
	for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
		// Check if the control message length is zero
		if (cmsgptr->cmsg_len == 0) {
			// Log an error message if reading ancillary data failed
			DBG1(DBG_NET, "error reading ancillary data");
			return NULL;
		}
		// Check if the control message is for IPv6 and contains packet info
		if (cmsgptr->cmsg_level == SOL_IPV6 && cmsgptr->cmsg_type == IPV6_PKTINFO) {
			// Declare a pointer for the packet info
			struct in6_pktinfo *pktinfo;
			// Declare a structure for the destination address
			struct sockaddr_in6 dst;
			// Get the packet info from the control message data
			pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsgptr);
			// Initialize the destination address structure
			memset(&dst, 0, sizeof(dst));
			// Copy the destination address from the packet info
			memcpy(&dst.sin6_addr, &pktinfo->ipi6_addr, sizeof(dst.sin6_addr));
			dst.sin6_family = AF_INET6;
			dst.sin6_port = htons(skt->port);
			// Create a host from the destination address
			dest = host_create_from_sockaddr((sockaddr_t*)&dst);
		}
		// Check if the control message is for IPv4 and contains packet info
		if (cmsgptr->cmsg_level == SOL_IP && cmsgptr->cmsg_type == IP_PKTINFO) {
			// Declare a pointer for the packet info
			struct in_pktinfo *pktinfo;
			// Declare a structure for the destination address
			struct sockaddr_in dst;
			// Get the packet info from the control message data
			pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsgptr);
			// Initialize the destination address structure
			memset(&dst, 0, sizeof(dst));
			// Copy the destination address from the packet info
			memcpy(&dst.sin_addr, &pktinfo->ipi_addr, sizeof(dst.sin_addr));
			dst.sin_family = AF_INET;
			dst.sin_port = htons(skt->port);
			// Create a host from the destination address
			dest = host_create_from_sockaddr((sockaddr_t*)&dst);
		}
		// If the destination host is created, break the loop
		if (dest) {
			break;
		}
	}
	// If the destination host is not created, log an error and return NULL
	if (dest == NULL) {
		DBG1(DBG_NET, "error reading IP header");
		return NULL;
	}
	// Create a host from the source address
	source = host_create_from_sockaddr((sockaddr_t*)&src);
	// Log the received packet with source and destination
	DBG2(DBG_NET, "received packet: from %#H to %#H", source, dest);
	// Create a chunk from the received data
	data = chunk_create(buffer, len);
	// Create a packet and set its source, destination, and data
	packet = packet_create();
	packet->set_source(packet, source);
	packet->set_destination(packet, dest);
	packet->set_data(packet, chunk_clone(data));
	// Return the created packet
	return packet;
}
// Method to receive packets
METHOD(socket_t, receiver, status_t, private_socket_dynamic_socket_t *this, packet_t **packet) {
	// Declare pointers for the selected socket and the received packet
	dynsock_t *selected;
	packet_t *pkt;
	// Declare a boolean for the old thread cancelability state
	bool oldstate;
	// Declare a file descriptor set
	fd_set fds;
	// Declare an integer for the maximum file descriptor
	int maxfd;
	// Loop to continuously check for incoming data
	while (TRUE) {
		// Build the file descriptor set and get the maximum file descriptor
		maxfd = build_fds(this, &fds);
		// Log a debug message indicating waiting for data on sockets
		DBG2(DBG_NET, "waiting for data on sockets");
		// Enable thread cancelability and save the old state
		oldstate = thread_cancelability(TRUE);
		// Wait for data on the sockets using select()
		if (select(maxfd, &fds, NULL, NULL, NULL) <= 0) {
			// Restore the old thread cancelability state
			thread_cancelability(oldstate);
			// Return FAILED if select() failed
			return FAILED;
		}
		// Restore the old thread cancelability state
		thread_cancelability(oldstate);
		// Check if the notification pipe's read end is set in the fd_set
		if (FD_ISSET(this->notify[0], &fds)) {	/* got notified, read garbage, rebuild fdset */
			// Declare a buffer to read garbage data
			char buf[1];
			// Read the garbage data from the notification pipe
			ignore_result(read(this->notify[0], buf, sizeof(buf)));
			// Log a debug message indicating rebuilding the fd_set
			DBG2(DBG_NET, "rebuilding fdset due to newly bound ports");
			// Continue to rebuild the fd_set
			continue;
		}
		// Scan the fd_set to find the selected socket
		selected = scan_fds(this, &fds);
		// If a socket is selected, break the loop
		if (selected) {
			break;
		}
	}
	// Receive a packet from the selected socket
	pkt = receive_packet(this, selected);
	// If a packet is received, set the packet pointer and return SUCCESS
	if (pkt) {
		*packet = pkt;
		return SUCCESS;
	}
	// Return FAILED if no packet is received
	return FAILED;
}
/**
 * Get the port allocated dynamically using bind()
 */
static bool get_dynamic_port(int fd, int family, uint16_t *port) {
	// Declare a union for the socket address
	union {
		struct sockaddr_storage ss;
		struct sockaddr s;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} addr;
	// Declare a variable for the length of the address
	socklen_t addrlen;
	// Initialize the length of the address
	addrlen = sizeof(addr);
	// Get the socket name (address and port) using getsockname()
	if (getsockname(fd, &addr.s, &addrlen) != 0) {
		// Log an error message if getsockname() failed
		DBG1(DBG_NET, "unable to getsockname: %s", strerror(errno));
		// Return FALSE if getsockname() failed
		return FALSE;
	}
	// Switch based on the address family
	switch (family)	{
		// Case for IPv4 address family
		case AF_INET:
			// Check if the address length and family are valid
			if (addrlen != sizeof(addr.sin) || addr.sin.sin_family != family) {
				break;
			}
			// Set the port from the address, converting from network to host byte order
			*port = ntohs(addr.sin.sin_port);
			// Return TRUE if the port is successfully set
			return TRUE;
		// Case for IPv6 address family
		case AF_INET6:
			// Check if the address length and family are valid
			if (addrlen != sizeof(addr.sin6) || addr.sin6.sin6_family != family) {
				break;
			}
			// Set the port from the address, converting from network to host byte order
			*port = ntohs(addr.sin6.sin6_port);
			// Return TRUE if the port is successfully set
			return TRUE;
		// Default case for unsupported address families
		default:
			// Return FALSE for unsupported families
			return FALSE;
	}
	// Log an error message if the getsockname() result is invalid
	DBG1(DBG_NET, "received invalid getsockname() result");
	// Return FALSE if the getsockname() result is invalid
	return FALSE;
}
/**
 * open a socket to send and receive packets
 */
static int open_socket(private_socket_dynamic_socket_t *this, int family, uint16_t *port) {
	// Declare a union for the socket address
	union {
		struct sockaddr_storage ss;
		struct sockaddr s;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} addr;
	// Declare a variable to enable socket options
	int on = TRUE;
	// Declare a variable for the length of the address
	socklen_t addrlen;
	// Declare variables for socket option level and packet info
	u_int sol, pktinfo = 0;
	// Declare a variable for the socket descriptor
	int fd;
	// Initialize the address structure to zero
	memset(&addr, 0, sizeof(addr));
	/* precalculate constants depending on address family */
	switch (family) {
		// Case for IPv4 address family
		case AF_INET:
			// Set the family, address, and port for the IPv4 address structure
			addr.sin.sin_family = AF_INET;
			addr.sin.sin_addr.s_addr = INADDR_ANY;
			addr.sin.sin_port = htons(*port);
			// Set the length of the address structure
			addrlen = sizeof(addr.sin);
			// Set the socket option level to SOL_IP for IPv4
			sol = SOL_IP;
			// Set the packet info option for IPv4
			pktinfo = IP_PKTINFO;
			break;
		// Case for IPv6 address family
		case AF_INET6:
			// Set the family and port for the IPv6 address structure, and clear the address
			addr.sin6.sin6_family = AF_INET6;
			memset(&addr.sin6.sin6_addr, 0, sizeof(addr.sin6.sin6_addr));
			addr.sin6.sin6_port = htons(*port);
			// Set the length of the address structure
			addrlen = sizeof(addr.sin6);
			// Set the socket option level to SOL_IPV6 for IPv6
			sol = SOL_IPV6;
			// Set the packet info option for IPv6
			pktinfo = IPV6_RECVPKTINFO;
			break;
		// Default case for unsupported address families
		default:
			// Return 0 if the family is unsupported
			return 0;
	}
	// Create a socket for the specified address family, using UDP protocol
	fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	// Check if socket creation failed
	if (fd < 0) {
		// Log an error message if socket creation failed
		DBG1(DBG_NET, "could not open socket: %s", strerror(errno));
		// Return 0 if socket creation failed
		return 0;
	}
	// If the address family is IPv6, set the IPV6_V6ONLY socket option
	if (family == AF_INET6 && setsockopt(fd, SOL_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
		// Log an error message if setting IPV6_V6ONLY failed
		DBG1(DBG_NET, "unable to set IPV6_V6ONLY on socket: %s", strerror(errno));
		// Close the socket
		close(fd);
		// Return 0 if setting IPV6_V6ONLY failed
		return 0;
	}
	// Bind the socket to the address and port
	if (bind(fd, &addr.s, addrlen) < 0)	{
		// Log an error message if binding the socket failed
		DBG1(DBG_NET, "unable to bind socket: %s", strerror(errno));
		// Close the socket
		close(fd);
		// Return 0 if binding the socket failed
		return 0;
	}
	// If the port is 0, get a dynamically allocated port
	if (*port == 0 && !get_dynamic_port(fd, family, port)) {
		// Close the socket
		close(fd);
		// Return 0 if getting the dynamic port failed
		return 0;
	}
	/* get additional packet info on receive */
	// Set the packet info option on the socket
	if (setsockopt(fd, sol, pktinfo, &on, sizeof(on)) < 0) {
		// Log an error message if setting packet info failed
		DBG1(DBG_NET, "unable to set IP_PKTINFO on socket: %s", strerror(errno));
		// Close the socket
		close(fd);
		// Return 0 if setting packet info failed
		return 0;
	}
	// Check if the kernel does not bypass the socket for IKE (Internet Key Exchange) traffic
	if (!charon->kernel->bypass_socket(charon->kernel, fd, family)) {
		// Log an error message if installing IKE bypass policy failed
		DBG1(DBG_NET, "installing IKE bypass policy failed");
	}
	/* enable UDP decapsulation on each socket */
	// Check if enabling UDP decapsulation fails
	if (!charon->kernel->enable_udp_decap(charon->kernel, fd, family, *port)) {
		// Log an error message if enabling UDP decapsulation failed
		DBG1(DBG_NET, "enabling UDP decapsulation for %s on port %d failed",
			 family == AF_INET ? "IPv4" : "IPv6", *port);
	}
	// Return the socket descriptor
	return fd;
}
/**
 * Get the first usable socket for an address family
 */
static dynsock_t *get_any_socket(private_socket_dynamic_socket_t *this, int family) {
	// Declare pointers for the key, value, and found socket
	dynsock_t *key, *value, *found = NULL;
	// Declare a pointer for the enumerator
	enumerator_t *enumerator;
	// Acquire a read lock on the sockets hashtable
	this->lock->read_lock(this->lock);
	// Create an enumerator for the sockets hashtable
	enumerator = this->sockets->create_enumerator(this->sockets);
	// Enumerate through all the key-value pairs in the hashtable
	while (enumerator->enumerate(enumerator, &key, &value)) {
		// Check if the socket's family matches the specified family
		if (value->family == family) {
			// Set the found socket to the current value
			found = value;
			// Break the loop as we found a matching socket
			break;
		}
	}
	// Destroy the enumerator
	enumerator->destroy(enumerator);
	// Release the read lock on the sockets hashtable
	this->lock->unlock(this->lock);
	// Return the found socket
	return found;
}
/**
 * Find/Create a socket to send from host
 */
static dynsock_t *find_socket(private_socket_dynamic_socket_t *this, int family, uint16_t port) {
	// Declare a pointer for the dynamic socket and initialize a lookup socket
	dynsock_t *skt, lookup = {
		.family = family,
		.port = port,
	};
	// Declare a buffer to notify the receiver thread
	char buf[] = {0x01};
	// Declare a variable for the socket descriptor
	int fd;
	// Acquire a read lock on the sockets hashtable
	this->lock->read_lock(this->lock);
	// Try to get the socket from the hashtable using the lookup key
	skt = this->sockets->get(this->sockets, &lookup);
	// Release the read lock on the sockets hashtable
	this->lock->unlock(this->lock);
	// If the socket is found in the hashtable, return it
	if (skt) {
		return skt;
	}
	// If the port is 0, try to get any socket for the specified family
	if (!port) {
		skt = get_any_socket(this, family);
		// If a socket is found, return it
		if (skt) {
			return skt;
		}
	}
	// Open a new socket for the specified family and port
	fd = open_socket(this, family, &port);
	// If opening the socket failed, return NULL
	if (!fd) {
		return NULL;
	}
	// Initialize the dynamic socket with the family, port, and file descriptor
	INIT(skt,
		.family = family,
		.port = port,
		.fd = fd,
	);
	// Acquire a write lock on the sockets hashtable
	this->lock->write_lock(this->lock);
	// Put the new socket into the hashtable
	this->sockets->put(this->sockets, skt, skt);
	// Release the write lock on the sockets hashtable
	this->lock->unlock(this->lock);
	/* notify receiver thread to reread socket list */
	// Write to the notification pipe to signal the receiver thread
	ignore_result(write(this->notify[1], buf, sizeof(buf)));
	// Return the new socket
	return skt;
}
/**
 * Generic function to send a message.
 */
static ssize_t send_msg_generic(int skt, struct msghdr *msg) {
	// Send a message using the sendmsg() system call
	return sendmsg(skt, msg, 0);
}
/**
 * Send a message with the IPv4 source address set.
 */
static ssize_t send_msg_v4(int skt, struct msghdr *msg, host_t *src) {
	// Declare a buffer for control message headers, initialized to zero
	char buf[CMSG_SPACE(sizeof(struct in_pktinfo))] = {};
	// Declare pointers for the control message header, IPv4 address, and packet info
	struct cmsghdr *cmsg;
	struct in_addr *addr;
	struct in_pktinfo *pktinfo;
	// Declare a pointer for the IPv4 socket address
	struct sockaddr_in *sin;
	// Set the control message buffer and its length in the message header
	msg->msg_control = buf;
	msg->msg_controllen = sizeof(buf);
	// Get the first control message header
	cmsg = CMSG_FIRSTHDR(msg);
	// Set the control message level to SOL_IP (IPv4)
	cmsg->cmsg_level = SOL_IP;
	// Set the control message type to IP_PKTINFO
	cmsg->cmsg_type = IP_PKTINFO;
	// Set the control message length
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	// Get the packet info from the control message data
	pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
	// Get the IPv4 address pointer from the packet info
	addr = &pktinfo->ipi_spec_dst;
	// Get the socket address from the source host
	sin = (struct sockaddr_in*)src->get_sockaddr(src);
	// Copy the source IPv4 address into the control message
	memcpy(addr, &sin->sin_addr, sizeof(struct in_addr));
	// Send the message using the generic send function
	return send_msg_generic(skt, msg);
}
/**
 * Send a message with the IPv6 source address set.
 */
static ssize_t send_msg_v6(int skt, struct msghdr *msg, host_t *src) {
	// Declare a buffer for control message headers, initialized to zero
	char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {};
	// Declare pointers for the control message header and packet info
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pktinfo;
	// Declare a pointer for the IPv6 socket address
	struct sockaddr_in6 *sin;
	// Set the control message buffer and its length in the message header
	msg->msg_control = buf;
	msg->msg_controllen = sizeof(buf);
	// Get the first control message header
	cmsg = CMSG_FIRSTHDR(msg);
	// Set the control message level to SOL_IPV6 (IPv6)
	cmsg->cmsg_level = SOL_IPV6;
	// Set the control message type to IPV6_PKTINFO
	cmsg->cmsg_type = IPV6_PKTINFO;
	// Set the control message length
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	// Get the packet info from the control message data
	pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsg);
	// Get the socket address from the source host
	sin = (struct sockaddr_in6*)src->get_sockaddr(src);
	// Copy the source IPv6 address into the control message
	memcpy(&pktinfo->ipi6_addr, &sin->sin6_addr, sizeof(struct in6_addr));
	// Send the message using the generic send function
	return send_msg_generic(skt, msg);
}
/**
 * Get type
 */
METHOD(socket_t, get_type, char*, private_socket_dynamic_socket_t *this) { return "udp"; }
// Method to send a packet
METHOD(socket_t, sender, status_t, private_socket_dynamic_socket_t *this, packet_t *packet) {
	// Declare pointers for the dynamic socket, source host, and destination host
	dynsock_t *skt;
	host_t *src, *dst;
	// Declare an integer for the address family
	int family;
	// Declare a variable for the length of the sent data
	ssize_t len;
	// Declare a chunk for the packet data
	chunk_t data;
	// Declare structures for the message header and IO vector
	struct msghdr msg;
	struct iovec iov;
	// Get the source and destination hosts from the packet
	src = packet->get_source(packet);
	dst = packet->get_destination(packet);
	// Get the address family from the source host
	family = src->get_family(src);
	// Find or create a socket for the specified family and port
	skt = find_socket(this, family, src->get_port(src));
	// If no socket is found, return FAILED
	if (!skt) {
		return FAILED;
	}
	// Get the data chunk from the packet
	data = packet->get_data(packet);
	// Log a debug message indicating the source and destination of the packet
	DBG2(DBG_NET, "sending packet: from %#H to %#H", src, dst);
	// Initialize the message header structure to zero
	memset(&msg, 0, sizeof(struct msghdr));
	// Set the destination address and length in the message header
	msg.msg_name = dst->get_sockaddr(dst);
	msg.msg_namelen = *dst->get_sockaddr_len(dst);
	// Set the data pointer and length in the IO vector
	iov.iov_base = data.ptr;
	iov.iov_len = data.len;
	// Attach the IO vector to the message header
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	// Clear any flags in the message header
	msg.msg_flags = 0;
	// If the source address is not a wildcard address
	if (!src->is_anyaddr(src)) {
		// If the address family is IPv4, send the message using the IPv4-specific function
		if (family == AF_INET) {
			len = send_msg_v4(skt->fd, &msg, src);
		}
		// If the address family is IPv6, send the message using the IPv6-specific function
		else {
			len = send_msg_v6(skt->fd, &msg, src);
		}
	}
	// If the source address is a wildcard address, send the message using the generic send function
	else {
		len = send_msg_generic(skt->fd, &msg);
	}
	// If the length of the sent data does not match the data length, log an error and return FAILED
	if (len != data.len) {
		DBG1(DBG_NET, "error writing to socket: %s", strerror(errno));
		return FAILED;
	}
	// Return SUCCESS if the data was sent successfully
	return SUCCESS;
}
// Method to get the port
METHOD(socket_t, get_port, uint16_t, private_socket_dynamic_socket_t *this, bool nat_t) {
	// Return 0 for users that have no explicit port configured, the sender will default to the default port in this case
	return 0;
}
// Method to get the supported address families
METHOD(socket_t, supported_families, socket_family_t, private_socket_dynamic_socket_t *this) {
	// Return both IPv4 and IPv6 families, even if no socket is yet open
	return SOCKET_FAMILY_BOTH;
}
// Method to destroy the socket
METHOD(socket_t, destroy, void, private_socket_dynamic_socket_t *this) {
	// Declare a pointer for the enumerator
	enumerator_t *enumerator;
	// Declare pointers for the key and value in the hashtable
	dynsock_t *key, *value;
	// Create an enumerator for the sockets hashtable
	enumerator = this->sockets->create_enumerator(this->sockets);
	// Enumerate through all the key-value pairs in the hashtable
	while (enumerator->enumerate(enumerator, &key, &value)) {
		// Close the socket file descriptor and free the dynamic socket
		close(value->fd);
		free(value);
	}
	// Destroy the enumerator
	enumerator->destroy(enumerator);
	// Destroy the sockets hashtable
	this->sockets->destroy(this->sockets);
	// Destroy the read-write lock
	this->lock->destroy(this->lock);
	// Close the notification pipe file descriptors
	close(this->notify[0]);
	close(this->notify[1]);
	// Free the private socket structure
	free(this);
}
/*
 * See header for description
 */
// Function to create a dynamic socket
socket_dynamic_socket_t *socket_dynamic_socket_create() {
	// Declare a pointer for the private socket dynamic socket structure
	private_socket_dynamic_socket_t *this;
	// Initialize the private socket dynamic socket structure
	INIT(this,
		// Initialize the public part of the structure
		.public = {
			.socket = {
				.send = _sender,                // Set the send method
				.receive = _receiver,           // Set the receive method
				.get_port = _get_port,          // Set the get_port method
				.supported_families = _supported_families,  // Set the supported_families method
				.destroy = _destroy,            // Set the destroy method
			},
		},
		// Create a read-write lock for the structure
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		// Get the maximum packet size from the settings, default to PACKET_MAX_DEFAULT
		.max_packet = lib->settings->get_int(lib->settings,
								"%s.max_packet", PACKET_MAX_DEFAULT, lib->ns),
	);
	// Create a notification pipe
	if (pipe(this->notify) != 0) {
		// Log an error message if creating the notification pipe failed
		DBG1(DBG_NET, "creating notify pipe for dynamic socket failed");
		// Free the private socket structure
		free(this);
		// Return NULL if creating the notification pipe failed
		return NULL;
	}
	// Create a hashtable for the sockets with a hash function and equals function, initial size 8
	this->sockets = hashtable_create((void*)hash, (void*)equals, 8);
	// Return the public part of the socket structure
	return &this->public;
}