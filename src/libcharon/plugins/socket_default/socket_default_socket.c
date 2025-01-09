/*
 * RIT WISP
 */
/* Define _GNU_SOURCE to ensure GNU extensions are available */
#define _GNU_SOURCE

/* Include the header for the default socket implementation */
#include "socket_default_socket.h"
/* Include necessary system headers for socket programming */
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
/* Include headers for daemon functionality and threading support */
#include <daemon.h>
#include <threading/thread.h>
/* Define constants for platforms where they are not defined */
#ifndef SOL_IP
    #define SOL_IP IPPROTO_IP
#endif
#define SA struct sockaddr
/* Define a struct to represent the private socket default socket */
typedef struct private_socket_default_socket_t private_socket_default_socket_t;
/**
 * Private data structure for a socket object
 */
struct private_socket_default_socket_t {
    /* Public functions for the socket */
    socket_default_socket_t public;
    /* Determins if connection is client or server */
    bool server;
    /* Determines if socket is active */
    bool active;
    bool listen;
    /* Configured port for server (or random, if initially 0) */
    uint16_t port_s;
    /* Configured port for client (or random, if initially 0) */
    uint16_t port_c ;
    /* Server socket */
    int server_skt;
    /* Client socket */
    int client_skt;
    /* Accepted Socket */
    int accepted_skt;
    // Holds Server addr struct
    struct {
        struct sockaddr_in sin;
        // Declare a variable to hold the length of the address
        socklen_t addrlen;
    } server_addr;
    // Holds Client addr struct
    struct {
        struct sockaddr_in sin;
        // Declare a variable to hold the length of the address
        socklen_t addrlen;
    } client_addr;
    /* DSCP value set on IPv4 socket */
    uint8_t dscp4;
    /* Maximum packet size to receive */
    int max_packet;
    /* TRUE if the source address should be set on outbound packets */
    bool set_source;
    /* TRUE to force sending source interface on outbound packets */
    bool set_sourceif;
    bool stream_prefix_sent;
    bool stream_prefix_received;
    char recv_buffer[65536];
    size_t buffer_len;
};
/**
 * Method to receive packets from a socket.
 * @param this   Pointer to the private socket object
 * @param packet Pointer to the received packet
 * @return Status of the receive operation
 */
METHOD(socket_t, receiver, status_t, private_socket_default_socket_t *this, packet_t **packet) {
    int skt;                                   // Socket file descriptor for communication
    bool oldstate;
    DBG2(DBG_NET, "waiting for data on sockets");
    oldstate = thread_cancelability(TRUE);
    // Check if first time run
    if (!this->listen && !this->active) {
        // Start listening on the server socket for incoming connections
        this->listen = true;
        if (listen(this->server_skt, 0) != 0) {
            // Log an error message if listen failed
            DBG1(DBG_NET, "unable to listen on socket: %s", strerror(errno));
            thread_cancelability(oldstate);
            close(this->server_skt);
            this->server_skt = -1;
            return FAILED;
        }
        if (!this->active) {
            DBG1(DBG_NET, "Server Socket Listening");
            this->accepted_skt = accept(this->server_skt, (SA*)&this->server_addr.sin, &this->server_addr.addrlen);
            if (this->accepted_skt < 0) {
                // Log an error message if binding the socket failed
                DBG1(DBG_NET, "unable to accept: %s", strerror(errno));
                thread_cancelability(oldstate);
                close(this->server_skt);
                this->server_skt = -1;
                return FAILED;
            }
            DBG1(DBG_NET, "This is the Server");
            this->server = true;
            this->active = true;
            close(this->client_skt);
            this->client_skt = -1;
            DBG1(DBG_NET, "Server Socket Accept");
        }
    }
    thread_cancelability(oldstate);
    if (this->listen && this->server) {
        skt = this->accepted_skt;
    } else {
        skt = this->client_skt;
    }
    if (skt != -1) { // If a socket is selected
        /* Receive data from the connected TCP socket */
        ssize_t bytes_read = recv(skt, this->recv_buffer + this->buffer_len, sizeof(this->recv_buffer) - this->buffer_len, 0);
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                DBG1(DBG_NET, "connection closed by peer");
            } else {
                DBG1(DBG_NET, "error reading socket: %s", strerror(errno));
            }
            return FAILED;
        }
        this->buffer_len += bytes_read;
        size_t offset = 0;
        while (offset < this->buffer_len) {
            size_t remaining = this->buffer_len - offset;
            // Handle the stream prefix if not yet received
            if (remaining < 6) {
                // Not enough data for the prefix, wait for more
                break;
            }
            if (!this->stream_prefix_received && this->server) { // Check if stream prefix is needed
                const char expected_stream_prefix[] = {0x49, 0x4b, 0x45, 0x54, 0x43, 0x50}; // "IKETCP"
                if (memcmp(this->recv_buffer + offset, expected_stream_prefix, 6) != 0) { // Compare prefixes
                    DBG1(DBG_NET, "Invalid stream prefix received"); // Log invalid prefix
                    return FAILED; // Return failure status
                }
                this->stream_prefix_received = true; // Mark prefix as received
                DBG1(DBG_NET, "MAGIC Value Found");
                offset += 6; // Move offset past the prefix
                remaining -= 6;
            }
            // Check if we have enough data for the Length field
            if (remaining < 2) {
                // Not enough data, wait for more
                break;
            }
            // Read the Length field (2 bytes, network byte order)
            uint16_t recv_length;
            memcpy(&recv_length, this->recv_buffer + offset, 2); // Copy Length field from buffer
            recv_length = ntohs(recv_length); // Convert Length to host byte order
            // Skip the Length field
            offset += 2; // Move offset past the Length field
            remaining -= 2;
            // Ensure that the full message has been received
            if (remaining < recv_length - 2) {
                // Not enough data for the full message, wait for more
                offset -= 2; // Move offset back to include the prefix + Length field next time
                break;
            }
            // Check the non-ESP marker
            if (memcmp(this->recv_buffer + offset, "\x00\x00\x00\x00", 4) != 0) { // Verify marker
                DBG1(DBG_NET, "Invalid non-ESP marker"); // Log invalid marker
                return FAILED; // Return failure status
            }
            offset += 4;
            // Extract the IKE message
            size_t ike_message_length = recv_length - 6;
            chunk_t ike_message = chunk_create(this->recv_buffer + offset, ike_message_length);
            offset += ike_message_length;
            DBG1(DBG_NET, "Received IKE message: %b", ike_message.ptr, ike_message.len);
            // Create source and destination host objects
            host_t *source = NULL;
            host_t *dest = NULL;
            struct sockaddr_storage peer_addr;
            socklen_t peer_addr_len = sizeof(peer_addr);
            if (getpeername(skt, (SA*)&peer_addr, &peer_addr_len) < 0) { // Get peer address
                DBG1(DBG_NET, "error getting peer address: %s", strerror(errno)); // Log error
                return FAILED; // Return failure status
            }
            source = host_create_from_sockaddr((sockaddr_t *)&peer_addr); // Create source host
            struct sockaddr_storage local_addr;
            socklen_t local_addr_len = sizeof(local_addr);
            if (getsockname(skt, (SA*)&local_addr, &local_addr_len) < 0) { // Get local address
                DBG1(DBG_NET, "error getting local address: %s", strerror(errno)); // Log error
                source->destroy(source); // Clean up source host
                return FAILED; // Return failure status
            }
            dest = host_create_from_sockaddr((sockaddr_t *)&local_addr); // Create destination host
            // Create and populate the packet object
            packet_t *pkt = packet_create(); // Allocate a new packet
            if (!pkt) { // Check if packet creation failed
                DBG1(DBG_NET, "error creating packet"); // Log error
                source->destroy(source); // Clean up source host
                dest->destroy(dest); // Clean up destination host
                return FAILED; // Return failure status
            }
            pkt->set_source(pkt, source); // Set packet source
            pkt->set_destination(pkt, dest); // Set packet destination
            pkt->set_data(pkt, chunk_clone(ike_message)); // Set packet data with cloned IKE message
            // Assign the packet to the output parameter
            *packet = pkt; // Output the packet
            break;
        }
        // Remove processed data from the buffer
        if (offset > 0) {
            memmove(this->recv_buffer, this->recv_buffer + offset, this->buffer_len - offset);
            this->buffer_len -= offset;
        }
    } else {                                                             // If no socket is selected
        // Should not happen, return failed status
        return FAILED;
    }
    return SUCCESS;
}
/**
 * Generic function to send a message.
 * @param skt The socket file descriptor to send the message on
 * @param msg Pointer to the message header structure
 * @return The number of bytes sent on success, or -1 on error
 */
static ssize_t send_msg_generic(int skt, struct msghdr *msg) {
    return sendmsg(skt, msg, 0); // Call the sendmsg system call with the socket and message header, flags set to 0
}
#if defined(IP_PKTINFO) // Check if either IP_PKTINFO or HAVE_IN6_PKTINFO is defined
    /**
     * Find the interface index a source address is installed on
     */
    static int find_srcif(host_t *src) { // Define a static function find_srcif that takes a host_t pointer src and returns an int
        char *ifname; // Declare a pointer to a char to hold the interface name
        int idx = 0;  // Initialize the interface index to 0
        if (charon->kernel->get_interface(charon->kernel, src, &ifname)) { // Check if the kernel can get the interface for the given source address
            idx = if_nametoindex(ifname); // Get the interface index from the interface name
            free(ifname);                 // Free the allocated memory for the interface name
        }
        return idx; // Return the interface index
    }
#endif /* IP_PKTINFO */ // End of conditional code block
/**
 * Send a message with the IPv4 source address set, if possible.
 */
static ssize_t send_msg_v4(private_socket_default_socket_t *this, int skt, struct msghdr *msg, host_t *src) {
    // Define a static function send_msg_v4 that takes a private_socket_default_socket_t pointer this, an int skt a a struct msghdr pointer msg, and a host_t pointer src, and returns an ssize_t
    char buf[CMSG_SPACE(sizeof(struct in_pktinfo))] = {}; // Create a buffer with enough space to hold an in_pktinfo structure
    struct cmsghdr *cmsg;                                 // Declare a pointer to a control message header
    struct in_addr *addr;                                 // Declare a pointer to an in_addr structure
    struct in_pktinfo *pktinfo;                           // Declare a pointer to an in_pktinfo structure
    struct sockaddr_in *sin;                              // Declare a pointer to a sockaddr_in structure
    msg->msg_control = buf;                               // Set the control buffer of the message
    msg->msg_controllen = sizeof(buf);                    // Set the length of the control buffer
    cmsg = CMSG_FIRSTHDR(msg);                            // Get the first control message header
    cmsg->cmsg_level = SOL_IP;                            // Set the control message level to SOL_IP
    cmsg->cmsg_type = IP_PKTINFO;                         // Set the control message type to IP_PKTINFO
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo)); // Set the control message length
    pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg); // Get the data of the control message and cast it to an in_pktinfo pointer
    if (this->set_sourceif) {                       // Check if the set_sourceif flag is set
        pktinfo->ipi_ifindex = find_srcif(src); // Set the interface index in the pktinfo structure using the find_srcif function
    }
    addr = &pktinfo->ipi_spec_dst; // Set the address pointer to the spec_dst field of the pktinfo structure
    sin = (struct sockaddr_in *)src->get_sockaddr(src);   // Get the sockaddr_in structure from the source host
    memcpy(addr, &sin->sin_addr, sizeof(struct in_addr)); // Copy the source address to the addr pointer
    // Construct the TCP-encapsulated IKE message
    // Create a chunk_t data structure from the iovec in msg
    chunk_t data = { .ptr = msg->msg_iov[0].iov_base, .len = msg->msg_iov[0].iov_len };
    // Calculate the length of the IKE message:
    uint16_t ike_message_length = data.len;
    // Check if the IKE message length is valid
    if (ike_message_length <= 1) {
        DBG1(DBG_NET, "Invalid IKE message length");
        return -1;
    }
    // Initialize total_length to the ike_message_length + length + nonesp
    uint16_t total_length = ike_message_length + 2 + 4;
    if (!this->stream_prefix_sent && !this->server) {
        total_length += 6;
    }
    // Initialize offset to 0
    size_t offset = 0;
    // Allocate memory for the send buffer with total_length
    char *send_buffer = malloc(total_length);
    // Check if memory allocation succeeded
    if (!send_buffer) {
        DBG1(DBG_NET, "error allocating send buffer");
        return -1;
    }
    // Include the stream prefix if needed
    if (!this->stream_prefix_sent && !this->server) {
        const char ike_prefix[] = {0x49, 0x4b, 0x45, 0x54, 0x43, 0x50}; // "IKETCP"
        // Copy the stream prefix into the send buffer
        memcpy(send_buffer + offset, ike_prefix, 6);
        // Set the flag indicating the stream prefix has been sent
        this->stream_prefix_sent = true;
        offset += 6;
    }
    // Set the Length field (network byte order)
    uint16_t length_field = htons(ike_message_length + 2 + 4);
    // Copy the Length field into the send buffer at the current offset
    memcpy(send_buffer + offset, &length_field, 2);
    // Increment offset by 2
    offset += 2;
    // Include the non-ESP marker (4 zero bytes)
    memset(send_buffer + offset, 0, 4);
    // Increment offset by 4
    offset += 4;
    // Copy the IKE message data into the send buffer at the current offset
    memcpy(send_buffer + offset, data.ptr, data.len);
    // Increment offset by the length of the data
    offset += data.len;
    // Update the iovec to point to the send_buffer
    msg->msg_iov[0].iov_base = send_buffer;
    msg->msg_iov[0].iov_len = offset;
    // Send the message using the send_msg_generic function and return the result
    int ret = send_msg_generic(skt, msg);
    // cleanup
    free(send_buffer);
    return ret;
}
// Define a method 'sender' for a 'socket_t' type, which returns a 'status_t' and takes
// a private socket structure and a packet as arguments
METHOD(socket_t, sender, status_t, private_socket_default_socket_t *this, packet_t *packet) {
    // Declare integer variables for source port, and socket
    int sport, skt;
    // Declare a chunk of data
    chunk_t data;
    // Declare pointers for source and destination hosts
    host_t *src, *dst;
    // Declare a message header structure
    struct msghdr msg;
    // Declare an IO vector structure
    struct iovec iov;
    // Declare a pointer to store DSCP (Differentiated Services Code Point) value
    uint8_t *dscp;
    // Get the source host from the packet
    src = packet->get_source(packet);
    // Get the destination host from the packet
    dst = packet->get_destination(packet);
    // Get the data chunk from the packet
    data = packet->get_data(packet);
    // Debug message to log the source and destination of the packet
    DBG2(DBG_NET, "sending packet: from %#H to %#H", src, dst);
    /* send data */
    // Get the source port from the source host
    sport = src->get_port(src);
    // Check if socket has been activated
    if (this->server) {
        // We are the server
        skt = this->accepted_skt;
    } else {
        if (!this->active) {
            DBG1(DBG_NET, "This is the Client");
            skt = this->client_skt;
            shutdown(this->server_skt, SHUT_RDWR);
            close(this->server_skt);
            this->server_skt = -1;
            this->active = true;
            struct sockaddr_in *dst_sockaddr = (struct sockaddr_in *)dst->get_sockaddr(dst);
            this->client_addr.sin.sin_addr.s_addr = dst_sockaddr->sin_addr.s_addr;
            this->client_addr.sin.sin_port = dst_sockaddr->sin_port;
            if (connect(skt, (SA*)&this->client_addr.sin, this->client_addr.addrlen) != 0) {
                // Log an error message if binding the socket failed
                DBG1(DBG_NET, "unable to connect: %s", strerror(errno));
                // Close the socket
                close(skt);
                skt = -1;
                return FAILED;
            }
            DBG1(DBG_NET, "Client Socket Connected");
            this->active = true;
        } else {
            skt = this->client_skt;
        }
    }
    // Set the DSCP value for IPv4
    dscp = &this->dscp4;
    // If no valid socket was found, log a debug message and return failed status
    if (skt == -1) {
        DBG1(DBG_NET, "no socket found to send IPv%d packet from port %d", AF_INET, 4, sport);
        return FAILED;
    }
    /* setting DSCP values per-packet in a cmsg seems not to be supported
     * on Linux. We instead setsockopt() before sending it, this should be
     * safe as only a single thread calls send().
     */
    // If the DSCP value for the socket does not match the DSCP value in the packet
    if (*dscp != packet->get_dscp(packet)) {
        // Declare a uint8_t for DSCP on other systems
        uint8_t ds4;
        // Get the DSCP value from the packet and shift it left by 2 bits
        ds4 = packet->get_dscp(packet) << 2;
        // Set the IP_TOS option on the socket to the new DSCP value
        if (setsockopt(skt, SOL_IP, IP_TOS, &ds4, sizeof(ds4)) == 0) {
            // Update the DSCP value in the socket structure
            *dscp = packet->get_dscp(packet);
        }
        // If setsockopt fails, log an error message
        else {
            DBG1(DBG_NET, "unable to set IP_TOS on socket: %s", strerror(errno));
        }
    }
    // Clear the message header structure
    memset(&msg, 0, sizeof(struct msghdr));
    // Set the destination address in the message header
    msg.msg_name = dst->get_sockaddr(dst);
    // Set the length of the destination address in the message header
    msg.msg_namelen = *dst->get_sockaddr_len(dst);
    // Set the data pointer and length in the IO vector
    iov.iov_base = data.ptr;
    iov.iov_len = data.len;
    // Attach the IO vector to the message header
    msg.msg_iov = &iov;
    // Set the number of IO vectors in the message header
    msg.msg_iovlen = 1;
    // Clear any flags in the message header
    msg.msg_flags = 0;
    // If setting the source address and the source address is not a wildcard
    if (this->set_source && !src->is_anyaddr(src)) {
        // Send the message using the IPv4-specific function
        send_msg_v4(this, skt, &msg, src);
    }
    // If not setting the source address or the source address is a wildcard
    else {
        // Send the message using the generic send function
        send_msg_generic(skt, &msg);
    }
    // Return success status
    return SUCCESS;
}
// Define a method 'get_port' for a 'socket_t' type
METHOD(socket_t, get_port, uint16_t, private_socket_default_socket_t *this, bool nat_t) {
    return this->server ? this->port_s : this->port_c;
}
// Define a method 'supported_families' for a 'socket_t' type
METHOD(socket_t, supported_families, socket_family_t, private_socket_default_socket_t *this) {
    return SOCKET_FAMILY_IPV4;
}
/**
 * open a socket to send and receive packets
 */
static int open_socket(private_socket_default_socket_t *this, uint16_t *port, char type) {
    // Declare a variable to enable socket options
    int on = TRUE;
    // Declare a union to hold socket address structures
    struct sockaddr_in sin;
    socklen_t addrlen;
    // Declare variables for socket option level and packet info
    u_int sol, pktinfo = 0;
    // Declare a variable for the socket descriptor
    int skt;
    // Initialize the address structure to zero
    memset(&sin, 0, sizeof(sin));
    // Set the socket option level to SOL_IP for IPv4
    sol = SOL_IP;
    #ifdef IP_PKTINFO
        // Set the packet info option for systems with IP_PKTINFO
        pktinfo = IP_PKTINFO;
    #endif
    // Create a socket for the specified address family, using UDP protocol
    skt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // Check if socket creation failed
    if (skt < 0) {
        // Log an error message if socket creation failed
        DBG1(DBG_NET, "could not open socket: %s", strerror(errno));
        // Return error code -1
        return -1;
    }
    // Set the Family to IPv4
    sin.sin_family = AF_INET;
    // Set the IPv4 address to any address (0.0.0.0)
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    // Set the IPv4 port, converting from host to network byte order
    sin.sin_port = htons(*port);
    // Set the length of the address structure
    addrlen = sizeof(sin);
    // Bind
    DBG1(DBG_NET, (type == 'C') ? "Client Socket Created" : "Server Socket Created");
    // Bind the server socket to the address and port
    if (bind(skt, (SA*)&sin, addrlen) != 0) {
        // Log an error message if binding the socket failed
        DBG1(DBG_NET, "unable to bind socket: %s", strerror(errno));
        close(skt);
        skt = -1;
        return -1;
    }
    /* retrieve randomly allocated port if needed */
    // If the port is set to 0 (indicating it should be randomly allocated)
    if (*port == 0) {
        // Retrieve the assigned port number using getsockname
        if (getsockname(skt, (SA*)&sin, &addrlen) != 0) {
            // Log an error message if getsockname failed
            DBG1(DBG_NET, "unable to determine port: %s", strerror(errno));
            // Close the socket
            close(skt);
            skt = -1;
            // Return error code -1
            return -1;
        }
        // Set the port from the address structure, converting from network to host byte order
        *port = ntohs(sin.sin_port);
    }
    DBG1(DBG_NET, "%c Socket Bound to Port: %d", type, *port);
    /* get additional packet info on receive */
    // If packet info is enabled
    if (pktinfo > 0) {
        // Set the packet info option on the socket
        if (setsockopt(skt, sol, pktinfo, &on, sizeof(on)) < 0) {
            // Log an error message if setting packet info failed
            DBG1(DBG_NET, "unable to set IP_PKTINFO on socket: %s", strerror(errno));
            // Close the socket
            close(skt);
            skt = -1;
            // Return error code -1
            return -1;
        }
    }
    // If the kernel does not bypass the socket for IKE (Internet Key Exchange) traffic
    if (!charon->kernel->bypass_socket(charon->kernel, skt, AF_INET)) {
        // Log an error message if installing IKE bypass policy failed
        DBG1(DBG_NET, "installing IKE bypass policy failed");
    }
    // define sock metadata
    if (type == 'S') {
        // Attach server addr
        this->server_addr.sin = sin;
        this->server_addr.addrlen = addrlen;
        this->server_skt = skt;
    } else {
        // Attach client addr
        this->client_addr.sin = sin;
        this->client_addr.addrlen = addrlen;
        this->client_skt = skt;
    }
    // Return the socket descriptor
    return skt;
}
/**
 * Open a socket pair (client and server)
 */
static void open_socketpair(private_socket_default_socket_t *this) {
    // Open a client socket
    open_socket(this, &this->port_c, 'C');
    // If opening the socket failed
    if (this->client_skt == -1) {
        // Log an error message indicating the failure to open the socket
        DBG1(DBG_NET, "could not open client socket");
    }
    // Open a server socket
    open_socket(this, &this->port_s, 'S');
    // If opening the socket failed
    if (this->server_skt == -1) {
        // Log an error message indicating the failure to open the socket
        DBG1(DBG_NET, "could not open server socket");
    }
}
// Define a method 'destroy' for a 'socket_t' type
METHOD(socket_t, destroy, void, private_socket_default_socket_t *this) {
    // If the client socket is valid (not -1)
    if (this->client_skt != -1) {
        // Close the client socket
        close(this->client_skt);
        // Set the socket to -1
        this->client_skt = -1;
    }
    // If the server socket is valid (not -1)
    if (this->server_skt != -1) {
        // Close the server socket
        close(this->server_skt);
        // Set the socket to -1
        this->server_skt = -1;
    }
    DBG1(DBG_NET, "Sockets have been destroyed");
    // Free the memory allocated for the private socket structure
    free(this);
}
/*
 * See header for description
 */
// Function to create a default socket
socket_default_socket_t *socket_default_socket_create() {
    // Declare a pointer to the private socket structure
    private_socket_default_socket_t *this;
    // Initialize the private socket structure
    INIT(this,
         // Initialize the public part of the structure
         .public =
             {
                 .socket =
                     {
                         .send = _sender,                           // Set the send method
                         .receive = _receiver,                      // Set the receive method
                         .get_port = _get_port,                     // Set the get_port method
                         .supported_families = _supported_families, // Set the supported_families method
                         .destroy = _destroy,                       // Set the destroy method
                     },
             },
         // Initialize the max_packet from settings, default to PACKET_MAX_DEFAULT
         .max_packet = lib->settings->get_int(lib->settings, "%s.max_packet", PACKET_MAX_DEFAULT, lib->ns),
         // Initialize set_source from settings, default to TRUE
         .set_source = lib->settings->get_bool(lib->settings, "%s.plugins.socket-default.set_source", TRUE, lib->ns),
         // Initialize set_sourceif from settings, default to FALSE
         .set_sourceif = lib->settings->get_bool(lib->settings, "%s.plugins.socket-default.set_sourceif", FALSE, lib->ns),
         /* Determins if connection is client or server */
         .server = false,
         /* Determines if socket is active */
         .active = false,
         /* Determines if socket has listened before */
         .listen = false,
         /* Configured port for server (or random, if initially 0) */
         .port_s = 500,
         /* Configured port for client (or random, if initially 0) */
         .port_c = 0,
         .stream_prefix_sent = false,
         .stream_prefix_received = false,
         .buffer_len = 0,
         );
    open_socketpair(this);
    if (this->server_skt == -1 || this->client_skt == -1) {
        DBG1(DBG_NET, "could not create both sockets");
        destroy(this);
        return NULL;
    }
    // Return the public part of the socket structure
    return &this->public;
}