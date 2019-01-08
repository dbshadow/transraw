#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include "transraw.h"

/*
 *	  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *	|    Destination Mac    |       Source Mac      |  Type |  Flag |
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *	| MsgID |                      Reserve                          |
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *	|                                                               |
 *	|                            Payload                            |
 *	|                                                               |
 *	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 */

int usage(void)
{
	const char buf[] =
		"\nUsage:\n"
		"transraw -l br-lan -o /tmp/output -s \"/usr/sbin/transraw-script\"\n"
		"transraw -b br-lan -f /etc/config/devsetup -t 5 -s \"/usr/sbin/transraw-script\"\n"
		"transraw -r br-lan -f /etc/config/wireless -m ff:ff:ff:ff:ff:ff -o /tmp/output -s \"/usr/sbin/transraw-script\"\n"
		"\nFeature options:\n"
		"       -f      The file name which is requested or broadcasted\n"
		"       -m      Destination Mac\n"
		"       -o      output file\n"
		"       -s      call back script or command\n"
		"       -r      request file on which interface\n"
		"       -l      listen on which interface\n"
		"       -b      broadcast on which interface\n"
		"       -t      timeout (seconds)\n"
		"       -h      Show this help\n\n";
	fputs(buf, stderr);
	return 1;
}

void callback(char *script, int flag)
{
	char cmd[BUFSIZ] = {};

	if (strlen(script) != 0) {
		sprintf(cmd, "%s %d &", script, flag);
		system(cmd);
	}
}

void genpid(char *pid)
{
	FILE *fp = NULL;

	fp = fopen(pid, "w");
	if (!fp) {
		perror("fopen");
		return;
	}

	fprintf(fp, "%d\n", getpid());
	fclose(fp);
}

void genfile(uint8_t *data, ssize_t len, char *output)
{
	FILE *fp = NULL;
	char cmd[BUFSIZ] = {};

	fp = fopen(DECODE_FILE, "w");
	if (!fp)
		return;

	fwrite(data, 1, len, fp);
	fclose(fp);

	/*TODO openssl lib*/
	sprintf(cmd, "openssl enc -aes-256-cbc -pass pass:'zXcVfr@Wsadeq!#' -in %s -out %s -d", DECODE_FILE, output);
	system(cmd);

	unlink(DECODE_FILE);
}

int genrand(void)
{
	struct timeb tb;

	ftime(&tb);
	srand(tb.time + tb.millitm);

	return rand();
}

int sendconfig(int sockfd, char *ifname, void *data, unsigned int len, u_char *mac, int flag, uint16_t msgid)
{
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUFSIZ];
	struct header *hdr;
	struct sockaddr_ll socket_address;
	FILE *fp = NULL;
	char cmd[BUFSIZ] = {};


	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUFSIZ);
	hdr = (struct header *) sendbuf;
	/* Ethernet header */

	hdr->eh.ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	hdr->eh.ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	hdr->eh.ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	hdr->eh.ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	hdr->eh.ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	hdr->eh.ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	hdr->eh.ether_dhost[0] = mac[0];
	hdr->eh.ether_dhost[1] = mac[1];
	hdr->eh.ether_dhost[2] = mac[2];
	hdr->eh.ether_dhost[3] = mac[3];
	hdr->eh.ether_dhost[4] = mac[4];
	hdr->eh.ether_dhost[5] = mac[5];

	/* Ethertype field */
	hdr->eh.ether_type = htons(T_NETWORK);
	hdr->flag = htons(flag);

	/*random Messag ID*/
	hdr->msgid = htons(msgid);

	tx_len += sizeof(struct header);

	/* Packet data */
	memcpy(sendbuf+tx_len, data, len);
	tx_len += len;

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;

	/* Destination MAC */
	socket_address.sll_addr[0] = mac[0];
	socket_address.sll_addr[1] = mac[1];
	socket_address.sll_addr[2] = mac[2];
	socket_address.sll_addr[3] = mac[3];
	socket_address.sll_addr[4] = mac[4];
	socket_address.sll_addr[5] = mac[5];

	/* Send packet */
	cprintf("Send to %02x:%02x:%02x:%02x:%02x:%02x\n",
			socket_address.sll_addr[0], socket_address.sll_addr[1],
			socket_address.sll_addr[2], socket_address.sll_addr[3],
			socket_address.sll_addr[4], socket_address.sll_addr[5]);

	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		perror("sendto");

	return 0;
}

void broadcast_mode(int sockfd, char *ifname, char *filename, int timeout, char *script)
{
	int i;
	ssize_t numbytes;
	uint8_t buf[BUFSIZ];
	uint16_t msgid;
	void *data = malloc(BUFSIZ);
	FILE *fp = NULL;
	char cmd[BUFSIZ];
	unsigned int len = 0;
	u_char mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	genpid(TRANSRAW_BCST_PID);

	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, IFNAMSIZ-1) == -1) {
		perror("SO_BINDTODEVICE");
		close(sockfd);
		goto exit;
	}

	/*every broadcast packet message ID should be the same*/
	msgid = genrand() % 0xffff;

	sprintf(cmd, "openssl enc -aes-256-cbc -pass pass:'zXcVfr@Wsadeq!#' -in %s -out %s -e", filename, ENCODE_FILE);
	system(cmd);

	fp = fopen(ENCODE_FILE, "r");
	if (!fp)
		goto exit;

	len = fread(data, 1, BUFSIZ, fp);

	while (timeout != 0) {
		sendconfig(sockfd, ifname, data, len, mac, F_BROADCAST, msgid);
		/*TODO unlimit timeout -1 -> 0*/
		if (timeout != -1)
			timeout--;
		sleep(1);
	}

	callback(script, F_BROADCAST);

	fclose(fp);
exit:
	unlink(TRANSRAW_BCST_PID);
	unlink(ENCODE_FILE);
	free(data);
}

static int daemonize(int nochdir, int noclose, int fd0, int fd1, int fd2)
{
	int ret = 0;
	int err = 0;
	pid_t pid;
	int tmpfd = -1;
	int nullfd = -1;
	int i;

	/* Call fork() the first time. */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		ret = -1;
		goto OUT;
	}
	/* Terminate the parent process. */
	if (pid > 0)
		_exit(EXIT_SUCCESS);

	/* Create a new session. */
	pid = setsid();
	if (pid < 0) {
		perror("setsid");
		ret = -1;
		goto OUT;
	}

	/* Call fork() the second time. */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		ret = -1;
		goto OUT;
	}

	/* Terminate the parent process. */
	if (pid > 0)
		_exit(EXIT_SUCCESS);

	/* Change current working directory is nochdir is zero. */
	if (nochdir == 0) {
		if (chdir("/") < 0) {
			perror("chdir");
			ret = -1;
			goto OUT;
		}
	}

	/* Reset umask. */
	umask(0);

	/* Redirect stdin, stdout, and stderr if noclose is zero. */
	if (noclose == 0) {
		/* Close file descriptors 0, 1, and 2 first. */
		for (tmpfd = 0; tmpfd <= 2; tmpfd++) {
			if (close(tmpfd) < 0) {
				perror("close");
				ret = -1;
				goto OUT;
			}
		}

		/*
		 * Open /dev/null if any one of fd0, fd1, and fd2 is
		 * less than 0.
		 */
		if (fd0 < 0 || fd1 < 0 || fd2 < 0) {
			nullfd = open("/dev/null", O_RDWR);
			if (nullfd == -1) {
				/* open() had set errno. */
				perror("open");
				ret = -1;
				goto OUT;
			}
		} else {
			nullfd = -1;
		}

		/* Redirect stdin, stdout, and stderr. */
		for (i = 0; i <= 2; i++) {
			switch (i) {
			case 0: /* stdin */
				tmpfd = fd0;
				break;
			case 1: /* stdout */
				tmpfd = fd1;
				break;
			case 2: /* stderr */
				tmpfd = fd2;
				break;
			}

			/* Redirect to /dev/null if tmpfd < 0 */
			if (tmpfd < 0)
				ret = dup2(nullfd, i);
			else
				ret = dup2(tmpfd, i);

			if (ret < 0) {
				perror("dup2");
				ret = -1;
				goto OUT_CLOSE_NULL;
			}
		}
	}

OUT:
	return ret;

OUT_CLOSE_NULL:
	if (nullfd >= 0)
		close(nullfd);

	return ret;
}

void listen_mode(int sockfd, char *ifname, char *output, char *script)
{
	int i;
	ssize_t numbytes;
	uint8_t buf[BUFSIZ];
	fd_set rfds;
	struct timeval tv;
	int retval;
	struct header *hdr;
	uint16_t msgid;
	uint16_t last_msgid;
	void *data = malloc(BUFSIZ);
	FILE *fp = NULL;
	char cmd[BUFSIZ] = {};
	unsigned int len = 0;

	if (daemonize(0, 0, -1, -1, -1) < 0)
		goto exit;

	genpid(TRANSRAW_PID);

	/* Bind to device */
/*
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, IFNAMSIZ - 1) == -1) {
		perror("SO_BINDTODEVICE");
		close(sockfd);
		return;
	}
*/

	while (1) {
		memset(buf, 0, BUFSIZ);
		numbytes = recvfrom(sockfd, buf, BUFSIZ, 0, NULL, NULL);

		hdr = (struct header *) buf;

		if (ntohs(hdr->flag) == F_REQUEST) {
			/*request packet, send the config file.*/
			cprintf("Correct Data:\n");
			for (i = 0; i < numbytes; i++)
				cprintf("%02x:", buf[i]);
			cprintf("\n");
			cprintf("%02x:%02x:%02x:%02x:%02x:%02x send a request for %s\n",
					hdr->eh.ether_shost[0], hdr->eh.ether_shost[1],
					hdr->eh.ether_shost[2], hdr->eh.ether_shost[3],
					hdr->eh.ether_shost[4], hdr->eh.ether_shost[5], &buf[PAYLOAD_OFFSET]);

			msgid = genrand() % 0xffff;

			sprintf(cmd, "openssl enc -aes-256-cbc -pass pass:'zXcVfr@Wsadeq!#' -in %s -out %s -e", &buf[PAYLOAD_OFFSET], ENCODE_FILE);
			system(cmd);

			fp = fopen(ENCODE_FILE, "r");
			if (!fp)
				goto exit;

			len = fread(data, 1, BUFSIZ, fp);

			sendconfig(sockfd, ifname, data, len, hdr->eh.ether_shost, F_RESPONSE, genrand() % 0xffff);

			callback(script, F_REQUEST);

		} else if (ntohs(hdr->flag) == F_BROADCAST && last_msgid != hdr->msgid) {
			/*receive broadcast packet, exec script only*/
			cprintf("GET BROADCAST PACKET\n");
			cprintf("Data:\n");
			for (i = 0; i < numbytes; i++)
				cprintf("%02x:", buf[i]);
			cprintf("\n");

			if (strlen(output) != 0)
				genfile(&buf[PAYLOAD_OFFSET], numbytes - PAYLOAD_OFFSET, output);

			last_msgid = hdr->msgid;

			callback(script, F_BROADCAST);

		} else if (last_msgid == hdr->msgid || ntohs(hdr->flag) == F_RESPONSE) {
			/*recv in request_mode*/
			cprintf("Ignore the packet.\n");
		} else {
			cprintf("Wrong data !\n");
			for (i = 0; i < numbytes; i++)
				cprintf("%02x:", buf[i]);
			cprintf("\n");
		}
	}

	fclose(fp);
exit:
	/*TODO use SIGTERM to remove pid automatically*/
	unlink(TRANSRAW_PID);	//maybe unuse now.
	unlink(ENCODE_FILE);
	free(data);
}

void request_mode(int sockfd, char *ifname, char *filename, u_char *mac, char *output, int timeout, char *script)
{
	struct header *hdr;
	uint8_t buf[BUFSIZ] = {};
	int i = 0;
	struct timeval tv;
	int retval;
	FILE *fp = NULL;
	char cmd[BUFSIZ] = {};
	fd_set rfds;
	ssize_t numbytes;
	int retry = 0;

	genpid(TRANSRAW_REQ_PID);
repeat:
	/* Send packet */
	sendconfig(sockfd, ifname, filename, strlen(filename), mac, F_REQUEST, genrand() % 0xffff);

	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);

	if (retval < 0) {
		perror("select()");
		goto exit;
	} else if (retval == 0) {

		if (timeout != 0) {
			if (retry == timeout)
				goto exit;
			retry++;
		}

		cprintf("No data within in %d seconds.\n", retry);

		goto repeat;
	} else {
		numbytes = recvfrom(sockfd, buf, BUFSIZ, 0, NULL, NULL);
		hdr = (struct header *) buf;
		/*FIXME: need checksum ?*/

		if (ntohs(hdr->flag) == F_RESPONSE) {
			cprintf("Data:\n");
			for (i = 0; i < numbytes; i++)
				cprintf("%02x:", buf[i]);
			cprintf("\n");
			if (strlen(output) != 0)
				genfile(&buf[PAYLOAD_OFFSET], numbytes - PAYLOAD_OFFSET, output);

			callback(script, F_RESPONSE);
		} else {
			cprintf("WRONG Data:\n");
			for (i = 0; i < numbytes; i++)
				cprintf("%02x:", buf[i]);
			goto repeat;
		}
	}

exit:
	unlink(TRANSRAW_REQ_PID);	//maybe unuse now.

	return;

}

int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUFSIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	char filename[BUFSIZ];
	char output[BUFSIZ];
	ssize_t numbytes;
	uint8_t buf[BUFSIZ];
	int i = 0, c;
	u_char mac[6];
	char cmd[BUFSIZ] = {};
	fd_set rfds;
	int listen = 0;
	char script[BUFSIZ];
	int broadcast = 0;
	int request = 0;
	int timeout = 0;
	char *p;

	/*FIXME check valid arg?*/
	while ((c = getopt(argc, argv, "f:m:o:r:l:s:t:b:h")) != -1) {
		switch (c) {
		case 'f':
			strcpy(filename, optarg);
			break;
		case 'm':
			p = strtok(optarg, ":");
			while (p != NULL && i != 6) {
				mac[i] = strtol(p, NULL, 16);
				p = strtok(NULL, ":");
				i++;
			}
			break;
		case 'r':
			request = 1;
			strcpy(ifname, optarg);
			break;
		case 'o':
			strcpy(output, optarg);
			break;
		case 'l':
			listen = 1;
			strcpy(ifname, optarg);
			break;
		case 's':
			strcpy(script, optarg);
			break;
		case 'b':
			broadcast = 1;
			strcpy(ifname, optarg);
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		default:
			usage();
			return 0;
		}
	}

	/* Open RAW socket to send on */
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(T_NETWORK));

	if ((sockfd == -1)) {
		perror("socket");
		return 0;
	}

	if (listen == 1)
		listen_mode(sockfd, ifname, output, script);
	else if (broadcast == 1)
		broadcast_mode(sockfd, ifname, filename, timeout, script);
	else if (request == 1)
		request_mode(sockfd, ifname, filename, mac, output, timeout, script);

	if (sockfd != -1)
		close(sockfd);

	return 0;
}
