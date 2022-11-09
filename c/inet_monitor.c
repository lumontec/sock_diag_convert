/*This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.*/

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>

//Kernel TCP states. /include/net/tcp_states.h
enum{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING 
};

static const char* tcp_states_map[]={
    [TCP_ESTABLISHED] = "ESTABLISHED",
    [TCP_SYN_SENT] = "SYN-SENT",
    [TCP_SYN_RECV] = "SYN-RECV",
    [TCP_FIN_WAIT1] = "FIN-WAIT-1",
    [TCP_FIN_WAIT2] = "FIN-WAIT-2",
    [TCP_TIME_WAIT] = "TIME-WAIT",
    [TCP_CLOSE] = "CLOSE",
    [TCP_CLOSE_WAIT] = "CLOSE-WAIT",
    [TCP_LAST_ACK] = "LAST-ACK",
    [TCP_LISTEN] = "LISTEN",
    [TCP_CLOSING] = "CLOSING"
};

//There are currently 11 states, but the first state is stored in pos. 1.
//Therefore, I need a 12 bit bitmask
#define TCPF_ALL 0xFFF

//Copied from libmnl source
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

static int send_query(int fd)
{
    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK
    };
    struct
    {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 idr;
    } req = {
        .nlh = {
            .nlmsg_len = sizeof(req),
            .nlmsg_type = SOCK_DIAG_BY_FAMILY,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP
        },
        .idr = {
            .sdiag_family = AF_INET,
            .sdiag_protocol = IPPROTO_TCP,
            .idiag_states = -1,
//            .idiag_states = TCPF_ALL & 
//                ~((1<<TCP_SYN_RECV) | (1<<TCP_TIME_WAIT) | (1<<TCP_CLOSE)),
            .idiag_ext = -1,
        }
    };
    struct iovec iov = {
        .iov_base = &req,
        .iov_len = sizeof(req)
    };
    struct msghdr msg = {
        .msg_name = (void *) &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    for (;;) {
        if (sendmsg(fd, &msg, 0) < 0) {
            if (errno == EINTR)
                continue;

            perror("sendmsg");
            return -1;
        }

        return 0;
    }
}


void parse_diag_msg(struct inet_diag_msg *diag_msg, int rtalen){
    struct rtattr *attr;
    struct tcp_info *tcpi;
    char local_addr_buf[INET6_ADDRSTRLEN];
    char remote_addr_buf[INET6_ADDRSTRLEN];
    struct passwd *uid_info = NULL;

    memset(local_addr_buf, 0, sizeof(local_addr_buf));
    memset(remote_addr_buf, 0, sizeof(remote_addr_buf));

    //(Try to) Get user info
    uid_info = getpwuid(diag_msg->idiag_uid);

    if(diag_msg->idiag_family == AF_INET){
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_src), 
            local_addr_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_dst), 
            remote_addr_buf, INET_ADDRSTRLEN);
    } else if(diag_msg->idiag_family == AF_INET6){
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_src),
                local_addr_buf, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_dst),
                remote_addr_buf, INET6_ADDRSTRLEN);
    } else {
        fprintf(stderr, "Unknown family\n");
        return;
    }

    if(local_addr_buf[0] == 0 || remote_addr_buf[0] == 0){
        fprintf(stderr, "Could not get required connection information\n");
        return;
    } 

    //Parse the attributes of the netlink message in search of the
    //INET_DIAG_INFO-attribute
    if(rtalen > 0){
        attr = (struct rtattr*) (diag_msg+1);

        while(RTA_OK(attr, rtalen)){
            if(attr->rta_type == INET_DIAG_INFO){
                //The payload of this attribute is a tcp_info-struct, so it is
                //ok to cast
                tcpi = (struct tcp_info*) RTA_DATA(attr);

                //Output some sample data
                fprintf(stdout, 
                        "state: %s, src: %s:%d, dst: %s:%d, retr: %u\n", 
                        tcp_states_map[tcpi->tcpi_state],
                        local_addr_buf, ntohs(diag_msg->id.idiag_sport), 
                        remote_addr_buf, ntohs(diag_msg->id.idiag_dport),
                        tcpi->tcpi_retrans
                        );
                fflush(stdout);

//                //Output some sample data
//                fprintf(stdout, 
//                        "state: %s, src: %s:%d, dst: %s:%d,  rtt: %gms, var: %gms, recv_rtt: %gms, user: %s, uid: %u, snd_cwnd: %u/%u\n", 
//                        tcp_states_map[tcpi->tcpi_state],
//                        local_addr_buf, ntohs(diag_msg->id.idiag_sport), 
//                        remote_addr_buf, ntohs(diag_msg->id.idiag_dport),
//                        (double) tcpi->tcpi_rtt/1000, 
//                        (double) tcpi->tcpi_rttvar/1000,
//                        (double) tcpi->tcpi_rcv_rtt/1000, 
//                        uid_info == NULL ? "Not found" : uid_info->pw_name,
//                        diag_msg->idiag_uid,
//                        tcpi->tcpi_unacked,
//                        tcpi->tcpi_snd_cwnd
//                        );

            }
            attr = RTA_NEXT(attr, rtalen); 
        }
    }
}


static int receive_responses(int fd)
{
    long buf[8192 / sizeof(long)];
    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK
    };
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = sizeof(buf)
    };
    int flags = 0;

    for (;;) {
        struct msghdr msg = {
            .msg_name = (void *) &nladdr,
            .msg_namelen = sizeof(nladdr),
            .msg_iov = &iov,
            .msg_iovlen = 1
        };

        ssize_t ret = recvmsg(fd, &msg, flags);

        if (ret < 0) {
            if (errno == EINTR)
                continue;

            perror("recvmsg");
            return -1;
        }
        if (ret == 0)
            return 0;

        const struct nlmsghdr *h = (struct nlmsghdr *) buf;

        if (!NLMSG_OK(h, ret)) {
            fputs("!NLMSG_OK\n", stderr);
            return -1;
        }

        for (; NLMSG_OK(h, ret); h = NLMSG_NEXT(h, ret)) {
            if (h->nlmsg_type == NLMSG_DONE)
                return 0;

            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *err = NLMSG_DATA(h);

                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
                    fputs("NLMSG_ERROR\n", stderr);
                } else {
                    errno = -err->error;
                    perror("NLMSG_ERROR");
                }

                return -1;
            }

            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
                fprintf(stderr, "unexpected nlmsg_type %u\n",
                        (unsigned) h->nlmsg_type);
                return -1;
            }

            parse_diag_msg(NLMSG_DATA(h), h->nlmsg_len);
        }
    }
}


int main(int argc, char *argv[]){
    int nl_sock = 0, numbytes = 0, rtalen = 0;
    struct nlmsghdr *nlh;
    uint8_t recv_buf[SOCKET_BUFFER_SIZE];
    struct inet_diag_msg *diag_msg;

    //Create the monitoring socket
    if((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1){
        perror("socket: ");
        return EXIT_FAILURE;
    }

    int ret = 0;

    for (;;) {

      int ret = send_query(nl_sock) || receive_responses(nl_sock);

      if (ret != 0) {
        close(nl_sock);
        return ret;
      }

      sleep(1);

    }

    return EXIT_SUCCESS;
}

