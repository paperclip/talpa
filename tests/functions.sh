
if [ "$testfunctionsincluded" = "yes" ]; then
    true
else
    _mount_fs="dummy"

    function get_mount_fs()
    {
        rc=1
        mnt="$1"

        exec 6<&0
        exec < /proc/mounts

        while read des fs type rest; do
            test "$fs" != "$mnt" -o "$type" = "rootfs" && continue
            _mount_fs="${type}"
            rc=0
            break
        done

        if test $rc -ne 0; then
            mnt=/
        fi

        rc=1

        exec 0>&6 6<&-

        exec 6<&0
        exec < /proc/mounts

        while read des fs type rest; do
            test "$fs" != "$mnt" -o "$type" = "rootfs" && continue
            _mount_fs="${type}"
            rc=0
            break
        done

        exec 0>&6 6<&-

        return $rc
    }

    function find_talpa_config
    {
        talpafs=""
        talpafstype=""
        talpaprocfs=""
        talpasecurityfs=""
        talpadualfs=""

        if [ -d /sys/kernel/security/talpa ]; then
            talpafstype=securityfs
            talpafs=/sys/kernel/security/talpa
            talpasecurityfs=yes
        fi

        if [ -d /proc/sys/talpa ]; then
            talpaprocfs=yes
            if [ "$talpafs" = "" ]; then
                talpafs=/proc/sys/talpa
                talpafstype=procfs
            else
                talpadualfs=yes
                talpafstype=dualfs
            fi
        fi

        export talpafs talpafstype talpaprocfs talpasecurityfs talpadualfs

        return 0
    }

    function tlp_insmod
    {
        insmod $*
        rc=$?
        find_talpa_config

        return $rc
    }

    find_talpa_config

    testfunctionsincluded=yes
fi
