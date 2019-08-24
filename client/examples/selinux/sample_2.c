#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    char *con;
    getcon(&con);
    printf("%s\n",con);
    printf("%s\n",context_type_get(context_new(con)));
    printf("%d\n",getpid());
    freecon(con);
    sleep(20);
}
