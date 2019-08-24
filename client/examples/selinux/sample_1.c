#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
/*    char *buf1, *buf2;
    struct stat sb;
    getfilecon("sample_file", &buf1);
    stat("sample_file", &sb);
    printf("%s\n",buf1);*/
    int fd = open("sample_file", O_RDWR);
    getchar();
/*    fgetfilecon(fd, &buf2);
    char type[50], object_class[50];
    printf("%s\n",buf2);
    printf("type %s\n",context_type_get(context_new(buf1)));
    printf("obj class %s\n",security_class_to_string(mode_to_security_class(sb.st_mode)));*/
    return 0;
}
