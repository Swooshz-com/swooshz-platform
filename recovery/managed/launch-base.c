#include "platform.h"

int swz_launch_base_validate(bool static_native, bool pam_absent, bool dm_verity_verified, bool selinux_enforcing) {
    if (!static_native || !pam_absent || !dm_verity_verified || !selinux_enforcing) return -1;
    return 0;
}
