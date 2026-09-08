#define _GNU_SOURCE

#include "platform.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SWZ_RECOVERY_COMMAND "swz-recovery-v1"

extern char **environ;

static int reject_nonempty_original_command(void)
{
    char **entry;
    const char prefix[] = "SSH_ORIGINAL_COMMAND=";

    for (entry = environ; entry != NULL && *entry != NULL; ++entry) {
        if (strncmp(*entry, prefix, sizeof(prefix) - 1U) == 0 &&
            (*entry)[sizeof(prefix) - 1U] != '\0') {
            return -1;
        }
    }
    return 0;
}

int main(void)
{
    if (reject_nonempty_original_command() != 0 ||
        swz_confine_component("dispatcher") != 0) {
        return 126;
    }
    environ = NULL;
    execl(SWZ_BOOTSTRAP_PATH, SWZ_BOOTSTRAP_PATH, (char *)NULL);
    return errno == ENOENT ? 127 : 126;
}

