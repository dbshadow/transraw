#ifndef __TRANSRAW_H_DEFINED
#define __TRANSRAW_H_DEFINED

#define DECODE_FILE     	"/tmp/decodefile"
#define ENCODE_FILE		"/tmp/encodefile"
#define TRANSRAW_PID		"/var/run/transraw.pid"
#define TRANSRAW_REQ_PID	"/var/run/transraw_req.pid"
#define TRANSRAW_BCST_PID	"/var/run/transraw_bcst.pid"

/* Network Type */
#define T_NETWORK	0x9487

/* Flag */
#define F_REQUEST	0x0001
#define F_RESPONSE	0x0002
#define F_BROADCAST	0x0003

#define PAYLOAD_OFFSET	sizeof(struct header)

struct header {
	struct ether_header eh;
	uint16_t flag;
	uint16_t msgid;
	uint8_t reserve[14];
};

#define cprintf(fmt, args...) do { \
	FILE *cfp = fopen("/dev/console", "w"); \
	if (cfp) { \
		fprintf(cfp, "\033[1;32m"fmt"\033[0m", ## args); \
		fclose(cfp); \
	} \
} while (0)

#endif // __TRANSRAW_H_DEFINED
