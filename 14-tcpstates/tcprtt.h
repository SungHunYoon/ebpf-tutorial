#ifndef __TCPRTT_H
#define __TCPRTT_H

#define MAX_SLOTS 27

struct hist {
	unsigned long long latency;
	unsigned long long cnt;
	unsigned int slots[MAX_SLOTS];
};

#endif
