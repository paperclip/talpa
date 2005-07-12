
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
