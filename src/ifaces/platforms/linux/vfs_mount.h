
#include <linux/version.h>
#include <linux/mount.h>

struct vfsmount* getParent(struct vfsmount* mnt);

int iterateFilesystems(struct vfsmount* root, int (*callback) (struct vfsmount* mnt, unsigned long flags, bool fromMount));

/**
 * @return borrowed reference to device name
 */
const char *getDeviceName(struct vfsmount* mnt);


struct dentry *getVfsMountPoint(struct vfsmount* mnt);
