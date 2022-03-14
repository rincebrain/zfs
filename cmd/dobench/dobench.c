#include <sys/spa.h>
#include <sys/zfs_context.h>
#include <sys/zfs_chksum.h>

int main(int argc, char** argv) {
    kernel_init(SPA_MODE_READ);
//    chksum_init();
}