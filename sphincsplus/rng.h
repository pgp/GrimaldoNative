#ifndef rng_h
#define rng_h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifndef _WIN32

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#else

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>
#include <bcrypt.h>
#include <sal.h>

#endif

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

void randombytes_init();
int randombytes(unsigned char *x, unsigned long long xlen);

#endif /* rng_h */
