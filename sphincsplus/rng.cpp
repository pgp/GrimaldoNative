#include "rng.h"


void handleErrors() {
    abort();
}

int randombytes_f;

void randombytes_init() {
#ifndef _WIN32
	randombytes_f = open("/dev/urandom", O_RDONLY);
	if (randombytes_f < 0) {
		perror("Unable to open /dev/urandom for getting entropy, exiting");
		exit(-1);
	}
#endif
}

#ifndef _WIN32
ssize_t readAll(int desc, void* buf_, size_t count) {
        uint8_t* buf = (uint8_t*)buf_;
        size_t alreadyRead = 0;
        size_t remaining = count;
        for(;;) {
            ssize_t curr = read(desc, buf+alreadyRead,remaining);
            if (curr <= 0) return curr; // EOF

            remaining -= curr;
            alreadyRead += curr;

            if (remaining == 0) return count; // all expected bytes read
        }
}
#endif

int randombytes(unsigned char *x, unsigned long long xlen) {
#ifndef _WIN32
if (readAll(randombytes_f, x, xlen) == xlen) return RNG_SUCCESS;
else handleErrors();
#else
	if (!NT_SUCCESS(BCryptGenRandom(NULL,x,xlen,BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
		handleErrors();
	}
#endif
    return RNG_SUCCESS;
}










