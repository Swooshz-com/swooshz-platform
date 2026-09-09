#define _GNU_SOURCE

#include "platform.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    int seed_fd = open(SWZ_PRODUCTION_SEED_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (seed_fd < 0 || swz_validate_seed_fd(seed_fd) != 0 ||
        swz_disable_dump_core() != 0 || swz_confine_component("launch-base") != 0) {
        close(seed_fd);
        return 126;
    }
    if (dup2(seed_fd, SWZ_SEED_FD) < 0 ||
        fcntl(SWZ_SEED_FD, F_SETFD, 0) < 0) {
        close(seed_fd);
        return 126;
    }
    if (seed_fd != SWZ_SEED_FD) {
        close(seed_fd);
    }
    execl(SWZ_SUPERVISOR_PATH, SWZ_SUPERVISOR_PATH, (char *)NULL);
    return errno == ENOENT ? 127 : 126;
}
