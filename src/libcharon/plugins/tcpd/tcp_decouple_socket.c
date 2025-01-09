//
// Created by RIT WISP on 3/8/24.
//
#include "tcp_decouple_socket.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>

#include <daemon.h>
#include <threading/thread.h>

typedef struct private_tcp_decouple_socket_t private_tcp_decouple_socket_t;

/**
 * Private data of an socket_t object
 */
struct private_tcp_decouple_socket {
    // Public functions
    tcp_decouple_socket_t public;
    // Configured port
    uint16_t port;
    //IPv4 socket
    int ipv4;
    // Maximum packet size to receive
    int max_packet;
    // TRUE if the source address should be set on outbound packets
    bool set_source;
    // TRUE to force sending source interface on outbound packets
    bool set_sourceif;
    // A counter to implement round-robin selection of read sockets
    u_int rr_counter;
};
/**
 * Get the destination IPv4 address of a received packet, depending on the
 * available mechanism.
 */
#ifdef IP_PKTINFO
static host_t *get_dst_v4(struct cmsghdr *cmsgptr, uint16_t port) {
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    struct in_pktinfo *pktinfo;
    struct in_addr *addr;
    if (cmsgptr->cmsg_type == IP_PKTINFO) {
        pktinfo = (struct in_pktinfo *) CMSG_DATA(cmsgptr);
        addr = &pktinfo->ipi_addr;
        memcpy(&dst.sin_addr, addr, sizeof(dst.sin_addr));
        return host_create_from_sockaddr((sockaddr_t *)&dst);
    }
    return NULL;
}
#else /* Removed IP_RECVDSTADDR for simplicity, will not be run on BSD/OSX env */
static host_t *get_dst_v4(struct cmsghdr *cmsgptr, uint16_t port) {
	return NULL;
}
#endif /* IP_PKTINFO || IP_RECVDSTADDR */
/**
 * Receive METHOD
 */
METHOD(socket_t, receiver, status_t, private_tcp_decouple_socket_t *this, packet_t **packet) {
    char buffer[this->max_packet];
    chunk_t data;
    packet_t *pkt;
    host_t *source = NULL, *dest = NULL;
    bool oldstate;
    int bytes_read = 0;
    uint16_t port = 4500;  // Specific port (TCP) to listen on
    struct pollfd pfd = {.fd = this->ipv4, .events = POLLIN};
    DBG2(DBG_NET, "waiting for data on IPv4 TCP socket (port %d)", port);
    oldstate = thread_cancelability(TRUE);
    if (poll(&pfd, 1, -1) <= 0) {
        DBG1(DBG_NET, "poll() error or timeout");
        return FAILED;
    }
    if (pfd.revents & POLLIN) {
        struct sockaddr_in src_addr;
        socklen_t addrlen = sizeof(src_addr);
        bytes_read = recv(this->ipv4, buffer, this->max_packet, 0);  // Use recv for TCP
        if (bytes_read < 0) {
            DBG1(DBG_NET, "error reading socket: %s", strerror(errno));
            return FAILED;
        }
        DBG3(DBG_NET, "received %d bytes", bytes_read);
        // Initialize ancillary data structures
        char ancillary[CMSG_SPACE(sizeof(struct in_pktinfo))];
        memset(ancillary, 0, sizeof(ancillary));  // Initialize ancillary buffer to zero
        // Setup msghdr structure for receiving ancillary data
        struct msghdr msg;
        memset(&msg, 0, sizeof(struct msghdr));  // Initialize msg to zero
        msg.msg_name = &src_addr;
        msg.msg_namelen = addrlen;
        msg.msg_iovlen = 0;  // No data is received into the IO vector for control messages
        msg.msg_control = ancillary;
        msg.msg_controllen = sizeof(ancillary);
        // Receive data and ancillary control messages
        bytes_read = recvmsg(this->ipv4, &msg, 0);
        if (bytes_read < 0) {
            DBG1(DBG_NET, "error receiving message: %s", strerror(errno));
            return FAILED;
        }
        // Process received control messages
        struct cmsghdr *cmsgptr;
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
            if (cmsgptr->cmsg_len == 0) {
                DBG1(DBG_NET, "error reading ancillary data");
                return FAILED;
            }
            if (cmsgptr->cmsg_level == IPPROTO_IP && cmsgptr->cmsg_type == IP_PKTINFO) {
                dest = get_dst_v4(cmsgptr, port);
                break;
            }
        }
        // Create packet and set source/destination
        source = host_create_from_sockaddr((sockaddr_t *)&src_addr);
        pkt = packet_create();
        if (!pkt) {
            DBG1(DBG_NET, "error creating packet");
            return FAILED;
        }
        pkt->set_source(pkt, source);
        pkt->set_destination(pkt, dest);
        DBG2(DBG_NET, "received packet: from %#H to %#H", source, dest);
        // Create chunk from received data and set in packet
        data = chunk_create(buffer, bytes_read);
        pkt->set_data(pkt, chunk_clone(data));
    } else {
        DBG1(DBG_NET, "unexpected event on socket");
        return FAILED;
    }
    // Return the packet
    *packet = pkt;
    return SUCCESS;
}
/**
 * Function to send a message.
 */
static ssize_t send_msg(int skt, struct msghdr *msg) {
    return sendmsg(skt, msg, 0);
}
/**
 * Find the interface index a source address is installed on
 */
#if defined(IP_PKTINFO)
static int find_srcif(host_t *src) {
    char *ifname;
    int idx = 0;
    if (charon->kernel->get_interface(charon->kernel, src, &ifname)) {
        idx = if_nametoindex(ifname);
        free(ifname);
    }
    return idx;
}
#endif /* IP_PKTINFO */
/**
 * Send a message with the IPv4 source address set, if possible.
 */
#ifdef IP_PKTINFO
static ssize_t send_msg_v4(private_tcp_decouple_socket_t *this, int skt, struct msghdr *msg, host_t *src) {
    char buf[CMSG_SPACE(sizeof(struct in_pktinfo))] = {};
    struct cmsghdr *cmsg;
    struct in_addr *addr;
    struct in_pktinfo *pktinfo;
    struct sockaddr_in *sin;
    msg->msg_control = buf;
    msg->msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(msg);
    cmsg->cmsg_level = SOL_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
    if (this->set_sourceif) {
        pktinfo->ipi_ifindex = find_srcif(src);
    }
    addr = &pktinfo->ipi_spec_dst;
    sin = (struct sockaddr_in*)src->get_sockaddr(src);
    memcpy(addr, &sin->sin_addr, sizeof(struct in_addr));
    return send_msg(skt, msg);
}
#else /* Removed IP_RECVDSTADDR and IP_SENDSRCADDR for simplicity, will not be run on BSD/OSX env */
static ssize_t send_msg_v4(private_tcpd_decouple_socket_t *this, int skt, struct msghdr *msg, host_t *src) {
	return send_msg(skt, msg);
}
#endif /* IP_PKTINFO */
/**
 * Sender METHOD
 */
METHOD(socket_t, sender, status_t, private_tcp_decouple_socket_t *this, packet_t *packet) {
    int skt = -1, family;
    ssize_t bytes_sent;
    chunk_t data;
    host_t *src, *dst;
    src = packet->get_source(packet);
    dst = packet->get_destination(packet);
    data = packet->get_data(packet);
    DBG2(DBG_NET, "sending packet: from %#H to %#H", src, dst);
    // Determine the socket and address family based on the source port and destination family
    int sport = src->get_port(src);
    family = dst->get_family(dst);
    // Choose the socket based on the source port and destination family
    if (sport == 0 || sport == this->port) {
        if (family == AF_INET) {
            skt = this->ipv4;
        } else {
            return FAILED; // Only support AF_INET (IPv4) addresses
        }
    }
    if (skt == -1) {
        DBG1(DBG_NET, "no socket found to send IPv4 packet from port %d", sport);
        return FAILED;
    }
    // Prepare message header and ancillary data for sending
    struct msghdr msg;
    struct iovec iov;
    char buffer[data.len];
    memcpy(buffer, data.ptr, data.len);
    // Setup message structure
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = dst->get_sockaddr(dst);
    msg.msg_namelen = *dst->get_sockaddr_len(dst);
    iov.iov_base = buffer;
    iov.iov_len = data.len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    // Call send_msg_v4 to send the message with IP_PKTINFO
    bytes_sent = send_msg_v4(this, skt, &msg, src);
    if (bytes_sent != data.len) {
        DBG1(DBG_NET, "error writing to socket: %s", strerror(errno));
        return FAILED;
    }
    return SUCCESS;
}
/**
 * Supported Families METHOD - IPv4
 */
METHOD(socket_t, supported_families, socket_family_t, private_tcp_decouple_socket_t *this) {
	socket_family_t families = SOCKET_FAMILY_NONE;
	if (this->ipv4 != -1) {
		families |= SOCKET_FAMILY_IPV4;
	}
	return families;
}
/**
 * open a socket to send and receive packets
 */
static int open_socket(private_tcp_decouple_socket_t *this, int family, uint16_t *port) {
    int on = 1; // Use 1 for boolean options
    union {
        struct sockaddr sockaddr;
        struct sockaddr_in sin;
    } addr;
    socklen_t addrlen;
    int skt;
    memset(&addr, 0, sizeof(addr));
    addr.sockaddr.sa_family = family;
    switch (family) {
        case AF_INET:
            addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin.sin_port = htons(*port);
            addrlen = sizeof(addr.sin);
            break;
        default:
            return -1; // Only supporting AF_INET (IPv4) for TCP
    }
    skt = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (skt < 0) {
        DBG1(DBG_NET, "could not open socket: %s", strerror(errno));
        return -1;
    }
    // Set socket option to allow reuse of address and port
    if (setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        DBG1(DBG_NET, "unable to set SO_REUSEADDR on socket: %s", strerror(errno));
        close(skt);
        return -1;
    }
    // Bind the socket
    if (bind(skt, &addr.sockaddr, addrlen) < 0) {
        DBG1(DBG_NET, "unable to bind socket: %s", strerror(errno));
        close(skt);
        return -1;
    }
    if (!charon->kernel->bypass_socket(charon->kernel, skt, family)) {
        DBG1(DBG_NET, "installing IKE bypass policy failed");
    }
    return skt;
}
/**
 * Destroy METHOD
 */
METHOD(socket_t, destroy, void, private_tcp_decouple_socket_t *this) {
	if (this->ipv4 != -1) {
		close(this->ipv4);
	}
	free(this);
}
/**
 * Get type
 */
METHOD(socket_t, get_type, char*, private_tcp_decouple_socket_t *this) {
    return "tcp";
}
/**
 *
 * @return
 */
METHOD(socket_t, get_port, uint16_t, private_tcp_decouple_socket_t *this, bool nat_t) {
    return this->port != 0;
}
/*
 * See header for description
 */
tcp_decouple_socket_t *tcp_decouple_socket_create() {
    private_tcp_decouple_socket_t *this;
    INIT(this,
        .public = {
            .socket = {
                .send = _sender,
                .receive = _receiver,
                .get_port = _get_port,
                .supported_families = _supported_families,
                .destroy = _destroy,
                .get_type - _get_type,
            },
        }
    );
    if (open_socket(this, AF_INET, &this->port) < 0) {
        DBG1(DBG_NET, "Error: failed to create tcp_decouple TCP socket");
        destroy(this);
        return NULL;
    }
    if (this->ipv4 == -1) {
        DBG1(DBG_NET, "could not create any sockets");
        destroy(this);
        return NULL;
    }
    return &this->public;
}
