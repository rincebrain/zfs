#ifndef _ZFS_DEPRECATED_H
#define _ZFS_DEPRECATED_H
#define strtok(...) strtok(__VA_ARGS__) __attribute__((deprecated("Use strtok_r(3) instead!")))
#define __xpg_basename(...) __xpg_basename(__VA_ARGS__) __attribute__((deprecated("basename(3) is underspecified. Use zfs_basename() instead!")))
#define basename(...) basename(__VA_ARGS__) __attribute__((deprecated("basename(3) is underspecified. Use zfs_basename() instead!")))
#define dirname(...) dirname(__VA_ARGS__) __attribute__((deprecated("dirname(3) is underspecified. Use zfs_dirnamelen() instead!")))
#define bcopy(...) bcopy(__VA_ARGS__) __attribute__((deprecated("bcopy(3) is deprecated. Use memcpy(3)/memmove(3) instead!")))
#define bcmp(...) bcmp(__VA_ARGS__) __attribute__((deprecated("bcmp(3) is deprecated. Use memcmp(3) instead!")))
#define bzero(...) bzero(__VA_ARGS__) __attribute__((deprecated("bzero(3) is deprecated. Use memset(3) instead!")))
#define asctime(...) asctime(__VA_ARGS__) __attribute__((deprecated("Use strftime(3) instead!")))
#define asctime_r(...) asctime_r(__VA_ARGS__) __attribute__((deprecated("Use strftime(3) instead!")))
#define gmtime(...) gmtime(__VA_ARGS__) __attribute__((deprecated("gmtime(3) isn't thread-safe. Use gmtime_r(3) instead!")))
#define localtime(...) localtime(__VA_ARGS__) __attribute__((deprecated("localtime(3) isn't thread-safe. Use localtime_r(3) instead!")))
#endif
