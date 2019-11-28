/*
This code was taken from the SPHINCS reference implementation and is public domain.
*/

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>

static int fd = -1;

void randombytes(unsigned char *x, unsigned long long xlen)
{
    int i;

    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom", O_RDONLY);
            if (fd != -1) {
                break;
            }
            sleep(1);
        }
    }

    while (xlen > 0) {
        if (xlen < 1048576) {
            i = xlen;
        }
        else {
            i = 1048576;
        }

        i = read(fd, x, i);
        if (i < 1) {
            sleep(1);
            continue;
        }

        x += i;
        xlen -= i;
    }
}
#else

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>
#include <bcrypt.h>
#include <sal.h>

void randombytes(unsigned char *x, unsigned long long xlen) {
	if (!NT_SUCCESS(BCryptGenRandom(NULL,x,xlen,BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
		exit(-1);
	}
}
#endif
