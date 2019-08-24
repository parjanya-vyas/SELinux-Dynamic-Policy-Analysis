#include <sys/types.h>
#include <sys/stat.h>
#include <asm/ptrace.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <pwd.h>
#include <string.h>
//#include <sched.h>
//#include <fcntl.h>
#include "preload.h"
#include "socket.h"

#define O_APPEND	02000
#define O_CREAT		0100

#define O_RDONLY    0
#define O_WRONLY    1
#define O_RDWR      2
#define AT_SYMLINK_NOFOLLOW   0x100   /* Do not follow symbolic links.  */


void myexit(int);

int get_open_mode_from_fd(int fd)
{
    char pathname[1024];
    char flags[10];
    sprintf(pathname,"/proc/%d/fdinfo/%d",getpid(),fd);

    FILE *fp = fopen(pathname,"r");
    char *line = NULL;
    size_t len=0, read=0;

    read = getline(&line, &len, fp);//skip first line
    read = getline(&line, &len, fp);//second line contains relevant info
    fclose(fp);

    char c = line[7];
    int count = 0;
    while(c>='0'&&c<='7')
    {
        flags[count++] = c;
        c = line[7+count];
    }
    return (flags[count-1]-'0');
}

int get_uid_from_pid(int pid) {
    char path[1024],uid[10],pid_char[10];
    char *line = NULL;
    size_t len=0, read=0;

    for(int i=0;i<10;i++)
        pid_char[i]=NULL;

    sprintf(pid_char, "%d", pid);

    strcpy(path, "/proc/");
    strcat(path, pid_char);
    strcat(path, "/status");
    FILE *fp = fopen(path,"r");

    if(!fp)
        return -1;

    while((read = getline(&line, &len, fp)) != -1)
    {
        if(line[0]=='U' && line[1]=='i' && line[2]=='d' && line[3]==':')
        {
            char c = line[5];
            int count = 0;
            while(c>='0'&&c<='9')
            {
                uid[count++] = c;
                c = line[5+count];
            }
            return atoi(uid);
        }
    }
    return -1;
}

int filter_processes(const struct dirent *cur_dir)
{
    if(cur_dir->d_type != DT_DIR)
        return 0;
    for(int i=0; i<strlen(cur_dir->d_name); i++)
    {
        if(!isdigit(cur_dir->d_name[i]))
            return 0;
    }

    return 1;
}

int get_all_permitted_pids_from_pid(int pid, char ***pids)
{
    int count=0;
    *pids = (char **)malloc(1024 * sizeof(char *));
    for(int i=0;i<1024;i++)
        (*pids)[i] = (char *)malloc(10 * sizeof(char));

    int cur_uid = get_uid_from_pid(pid);

    struct dirent **namelist;
    int n = scandir("/proc", &namelist, &filter_processes, alphasort);

    if(n<0)
        printf("Error!");
    else
    {
        while(n--)
        {
            if((cur_uid == 0 || get_uid_from_pid(atoi(namelist[n]->d_name)) == cur_uid) && pid != atoi(namelist[n]->d_name))
                strcpy((*pids)[count++], namelist[n]->d_name);

            free(namelist[n]);
        }

        free(namelist);
    }

    return count;
}

int get_group_pids_from_pid(int pid, char ***pids)
{
    int count=0;
    *pids = (char **)malloc(1024 * sizeof(char *));
    for(int i=0;i<1024;i++)
        (*pids)[i] = (char *)malloc(10 * sizeof(char));

    struct dirent **namelist;
    int n = scandir("/proc", &namelist, &filter_processes, alphasort);

    int pgid = (pid>=0 ? getpgid(pid) : (-pid));

    if(n<0)
        printf("Error!");
    else
    {
        while(n--)
        {
            if((getpgid(atoi(namelist[n]->d_name)) == pgid) && (atoi(namelist[n]->d_name) != pid))
                strcpy((*pids)[count++], namelist[n]->d_name);

            free(namelist[n]);
        }

        free(namelist);
    }

    return count;
}

void *get_libc() {
    static void *libc_handle = 0;
    if (!libc_handle) {
        libc_handle = dlopen(LIBC, RTLD_LAZY);
    }
    return libc_handle;
}

void mygetcon(char * con) {
    sprintf(con,"kernel_t");
}

int myopen(const char *pathname, int flags) {
    static int (*underlying)(const char *pathname, int flags) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "open");
    }
    return (*underlying)(pathname, flags);
}

int mysocket(int domain, int type, int protocol) {
    static int (*underlying)(int , int , int ) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "socket");
    }
    return (*underlying)(domain, type, protocol);
}

int mybind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*underlying)(int , const struct sockaddr * , socklen_t ) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "bind");
    }
    return (*underlying)(sockfd, addr, addrlen);
}

int myconnect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    static int (*underlying)(int ,const struct sockaddr* , socklen_t ) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "connect");
    }
    return (*underlying)(sockfd, addr, addrlen);
}

ssize_t mysend(int sockfd, const void *buf, size_t len, int flags) {
    static int (*underlying)(int ,const void * , size_t, int ) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "send");
    }
    return (*underlying)(sockfd, buf, len, flags);
}

ssize_t myrecv(int sockfd, void *buf, size_t len, int flags) {
    static int (*underlying)(int ,void * , size_t, int ) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "recv");
    }
    return (*underlying)(sockfd, buf, len, flags);
}

ssize_t mywrite(int fd, const void *buf, size_t count) {
    static ssize_t (*underlying)(int, const void *, size_t) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "write");
    }
    return (*underlying)(fd, buf, count);
}

ssize_t myread(int fd, const void *buf, size_t count) {
    static ssize_t (*underlying)(int, const void *, size_t) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "r");
    }
    return (*underlying)(fd, buf, count);
}

void debuglog(char *log) {
    int logfd;
    logfd = myopen("/tmp/preload.log", 02000|02);
    mywrite(logfd, log, strlen(log));
    close(logfd);
}

int skip(const char *pathname){
    char token[10];
    int i=0;
    token[0]='\0';
    while(pathname[0]=='/' || pathname[0]=='.')
        pathname++;

    while(pathname[0]!='\0' && pathname[0]!='/'){
        token[i++] = pathname[0];
        pathname++;
    }
    token[i]='\0';

    if(strcmp(token, "proc")==0 || strcmp(token, "sys")==0)
        return 1;
    return 0;
}

int rwfm_process(char *op){
    char buf[50];
    int ret=1;
    if(rwfm_connect()<0){
        printf("\nCould not connect %d", rwfm_sockfd);
        return 1;
        //myexit(1);
    }
    mysend(rwfm_sockfd, op, strlen(op), 0);
    myrecv(rwfm_sockfd, buf, MAXDATASIZE-1, 0);
    ret = atoi(buf);
    /*if(ret==1)
        printf("\nPass.\n");
    else{
        printf("\nFail.\n");
        exit(1);
    }*/
    close(rwfm_sockfd);
    return(ret);
}

void exit_group(int status) {
    char buf[50];
    void (*underlying)(int) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "exit_group");
    }
#ifdef DEBUG
    sprintf(buf, "\nexit_group \n\tUID : %ld \n\tPID : %ld", (long)getuid(), (long)getpid());
	debuglog(buf);
#endif
    sprintf(buf, "exit_group %ld %ld", (long)getuid(), (long)getpid());
    rwfm_process(buf);
    (*underlying)(status);
}

void exit(int status) {
    char buf[50];
    void (*underlying)(int) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "exit");
    }
#ifdef DEBUG
    sprintf(buf, "\nexit \n\tUID : %ld \n\tPID : %ld", (long)getuid(), (long)getpid());
	debuglog(buf);
#endif
    sprintf(buf, "exit %ld %ld", (long)getuid(), (long)getpid());
    rwfm_process(buf);
    (*underlying)(status);
}

void _exit(int status){
    char buf[50];
    void (*underlying)(int) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "_exit");
    }
#ifdef DEBUG
    sprintf(buf, "\n_exit \n\tUID : %ld \n\tPID : %ld", (long)getuid(), (long)getpid());
	debuglog(buf);
#endif
    sprintf(buf, "_exit %ld %ld", (long)getuid(), (long)getpid());
    rwfm_process(buf);
    (*underlying)(status);
}

void _Exit(int status){
    char buf[50];
    void (*underlying)(int) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "_Exit");
    }
#ifdef DEBUG
    sprintf(buf, "\n_Exit \n\tUID : %ld \n\tPID : %ld", (long)getuid(), (long)getpid());
	debuglog(buf);
#endif
    sprintf(buf, "_Exit %ld %ld", (long)getuid(), (long)getpid());
    rwfm_process(buf);
    (*underlying)(status);
}

void myexit(int status) {
    void (*underlying)(int) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "exit");
    }
    (*underlying)(status);
}

int open64(const char *pathname, int flags, mode_t mode) {
    struct stat sb;
    char buf[1024];
    int exists=0;
    int ret=0;
    static int (*underlying)(const char *pathname, int flags, mode_t mode) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "open64");
    }
#ifdef DEBUG
	sprintf(buf, "\nopen64 \n\tpathname:%s, \n\tflags:%d, \n\tmode:%lo", pathname, flags, (unsigned long)mode);
	debuglog(buf);
#endif
    if(!skip(pathname) && stat(pathname, &sb)==0){
        exists=1;
        sprintf(buf, "open64 %ld %ld %ld %ld %lo",
                (long)sb.st_dev, (long)sb.st_ino,
                (long)sb.st_uid, (long)sb.st_gid, (unsigned long)sb.st_mode);
        if(!rwfm_process(buf))
            return -1;
    }

    ret = (*underlying)(pathname, flags, mode);
    if(ret==-1)
        return -1;

    if(!skip(pathname) && flags & O_CREAT && !exists){
        stat(pathname, &sb);
        sprintf(buf, "creat %ld %ld %ld %ld",
                (long)getuid(), (long)getpid(),
                (long)sb.st_dev, (long)sb.st_ino);
        if(!rwfm_process(buf))
            return -1;
    }
    return ret;
}

int open(const char *pathname, int flags) {
    struct stat sb;
    char buf[1024], *file_con, *proc_con;
    int exists=0;
    int ret=0;
    static int (*underlying)(const char *pathname, int flags) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "open");
    }
#ifdef DEBUG
	sprintf(buf, "\nopen \n\tpathname:%s, \n\tflags:%d", pathname, flags);
	debuglog(buf);
#endif
    char op[5];

    if(flags & O_RDWR)
        strcpy(op, "rw");
    else if(flags & O_WRONLY)
        strcpy(op, "w");
    else
        strcpy(op, "r");

    if(!skip(pathname) && stat(pathname, &sb)==0){
        exists=1;
        getfilecon(pathname, &file_con);
        getcon(&proc_con);
        sprintf(buf, "open %s %s %ld %ld %ld %s:%s %ld %lo", op,
                context_type_get(context_new(proc_con)), (long)getpid(),
                (long)sb.st_dev, (long)sb.st_ino,
                context_type_get(context_new(file_con)), security_class_to_string(mode_to_security_class(sb.st_mode)), (long)sb.st_gid, (unsigned long)sb.st_mode);
        freecon(proc_con);
        if(!rwfm_process(buf))
            return -1;
    }

    ret = (*underlying)(pathname, flags);
    if(ret==-1)
        return -1;

    if(!skip(pathname) && flags & O_CREAT && !exists){
        stat(pathname, &sb);
        sprintf(buf, "creat %ld %ld %ld %ld",
                (long)getuid(), (long)getpid(),
                (long)sb.st_dev, (long)sb.st_ino);
        if(!rwfm_process(buf))
            return -1;
    }
    return ret;
}
/*
int open(const char *pathname, int flags) {
    struct stat sb;
    char buf[1024], *con;
    int exists=0;
    int ret=0;
    static int (*underlying)(const char *pathname, int flags) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "open");
    }
#ifdef DEBUG
	sprintf(buf, "\nopen \n\tpathname:%s, \n\tflags:%d", pathname, flags);
	debuglog(buf);
#endif
    if(!skip(pathname) && stat(pathname, &sb)==0){
        exists=1;
        getfilecon(pathname, &con);
        sprintf(buf, "open %ld %ld %s:%s %ld %lo",
                (long)sb.st_dev, (long)sb.st_ino,
                context_type_get(context_new(con)), security_class_to_string(mode_to_security_class(sb.st_mode)),
                (long)sb.st_gid, (unsigned long)sb.st_mode);
        if(!rwfm_process(buf))
            return -1;
    }

    ret = (*underlying)(pathname, flags);
    if(ret==-1)
        return -1;

    if(!skip(pathname) && flags & O_CREAT && !exists){
        stat(pathname, &sb);
        sprintf(buf, "creat %ld %ld %ld %ld",
                (long)getuid(), (long)getpid(),
                (long)sb.st_dev, (long)sb.st_ino);
        if(!rwfm_process(buf))
            return -1;
    }
    return ret;
}
*/
int openat(int dirfd, const char *pathname, int flags){
    struct stat sb;
    char buf[1024];
    int exists=0;
    int ret=0;
    static int (*underlying)(int dirfd, const char *pathname, int flags) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "openat");
    }
#ifdef DEBUG
	sprintf(buf, "\nopenat \n\tpathname:%s, \n\tflags:%d", pathname, flags);
	debuglog(buf);
#endif
    if(fstatat(dirfd, pathname, &sb, 0)==0){
        exists=1;
        sprintf(buf, "open %ld %ld %ld %ld %lo",
                (long)sb.st_dev, (long)sb.st_ino,
                (long)sb.st_uid, (long)sb.st_gid, (unsigned long)sb.st_mode);
        if(!rwfm_process(buf))
            return -1;
    }

    ret = (*underlying)(dirfd, pathname, flags);
    if(ret==-1)
        return -1;

    if(flags & O_CREAT && !exists){
        fstatat(dirfd, pathname, &sb, 0);
        sprintf(buf, "creat %ld %ld %ld %ld",
                (long)getuid(), (long)getpid(),
                (long)sb.st_dev, (long)sb.st_ino);
        if(!rwfm_process(buf))
            return -1;
    }
    return ret;
}
/*
ssize_t read(int fd, void *buf, size_t count) {
    struct stat sb;
    char buff[1024], con[50], *cont;
    int ret=0;
    static ssize_t (*underlying)(int, void *, size_t) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "read");
    }
#ifdef DEBUG
	sprintf(buff, "\nread \n\tfd:%d, \n\tcount:%d", fd, count);
	debuglog(buff);
#endif

    if(fstat(fd, &sb)==0){
        if(S_ISREG(sb.st_mode))
        {
//            perror("Error:");
            mygetcon(con);
            getcon(&cont);
            sprintf(buff, "read %s %ld %ld %ld",
                    con, (long)getpid(),
                    (long)sb.st_dev, (long)sb.st_ino);
            //freecon(con);
            if(!rwfm_process(buff))
                return -1;
        }
    }

    return (*underlying)(fd, buf, count);
}
*/
ssize_t write(int fd, const void *buf, size_t count) {
    struct stat sb;
    char buff[1024], *con;
    int ret=0;
    static ssize_t (*underlying)(int, const void *, size_t) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "write");
        if(!underlying)
            printf("%s\n",dlerror());
    }

#ifdef DEBUG
	sprintf(buff, "\nwrite \n\tfd:%d, \n\tcount:%d", fd, count);
	debuglog(buff);
#endif
    if(fstat(fd, &sb)==0){
        if(S_ISREG(sb.st_mode))
        {
            getcon(&con);
            sprintf(buff, "write %d %s %ld %ld %ld", get_open_mode_from_fd(fd),
                    context_type_get(context_new(con)), (long)getpid(),
                    (long)sb.st_dev, (long)sb.st_ino);
            freecon(con);
            if(!rwfm_process(buff))
                return -1;
            else
                return (*underlying)(fd, buf, count);
        }
        else
            return (*underlying)(fd, buf, count);
    }

}

int get_operation_type(const char *mode){
    int create=0;
    if(strcmp(mode, "w")==0 || strcmp(mode, "wb")==0 ||
       strcmp(mode, "a")==0 || strcmp(mode, "ab")==0){
        create = 1;
    }else if(strcmp(mode, "+w")==0 || strcmp(mode, "+wb")==0 ||
            strcmp(mode, "wb+")==0 || strcmp(mode, "w+b")==0 ||
            strcmp(mode, "a+")==0 || strcmp(mode, "ab+")==0 ||
            strcmp(mode, "a+b")==0){ 
        create = 1;
    }else{
        create = -1;
    }
    return create;
}

FILE *fopen(const char *pathname, const char *mode) {
    struct stat sb;
    char buf[1024];
    int exists = 0;
    int create = 0;
    FILE *fp = NULL;
    static FILE * (*underlying)(const char *pathname, const char *mode) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "fopen");
    }
#ifdef DEBUG
	sprintf(buf, "\nfopen \n\tpathname:%s, \n\tmode:%s", pathname, mode);
	debuglog(buf);
#endif

    create = get_operation_type(mode);

    if(!skip(pathname) && stat(pathname, &sb)==0){
        exists=1;
        sprintf(buf, "fopen %ld %ld %ld %ld %lo",
                (long)sb.st_dev, (long)sb.st_ino,
                (long)sb.st_uid, (long)sb.st_gid, (unsigned long)sb.st_mode);
        if(!rwfm_process(buf))
            return NULL;
    }

    fp = (*underlying)(pathname, mode);
    if(fp==NULL)
        return NULL;

    if(!skip(pathname) && create && !exists){
        stat(pathname, &sb);
        sprintf(buf, "creat %ld %ld %ld %ld",
                (long)getuid(), (long)getpid(),
                (long)sb.st_dev, (long)sb.st_ino);
        if(!rwfm_process(buf))
            return NULL;
    }
    return fp;
}

FILE *fopen64(const char *pathname, const char *mode) {
    struct stat sb;
    char buf[1024];
    int exists = 0;
    int create = 0;
    FILE *fp = NULL;
    static FILE * (*underlying)(const char *pathname, const char *mode) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "fopen64");
    }
#ifdef DEBUG
	sprintf(buf, "\nfopen64 \n\tpathname:%s, \n\tmode:%s", pathname, mode);
	debuglog(buf);
#endif

    create = get_operation_type(mode);

    if(!skip(pathname) && stat(pathname, &sb)==0){
        exists=1;
        sprintf(buf, "fopen64 %ld %ld %ld %ld %lo",
                (long)sb.st_dev, (long)sb.st_ino,
                (long)sb.st_uid, (long)sb.st_gid, (unsigned long)sb.st_mode);
        if(!rwfm_process(buf))
            return NULL;
    }

    fp = (*underlying)(pathname, mode);
    if(fp==NULL)
        return NULL;

    if(!skip(pathname) && create && !exists){
        stat(pathname, &sb);
        sprintf(buf, "creat %ld %ld %ld %ld",
                (long)getuid(), (long)getpid(),
                (long)sb.st_dev, (long)sb.st_ino);
        if(!rwfm_process(buf))
            return NULL;
    }
    return fp;
}

pid_t fork(void){
    char buf[50], *con;
    static int (*underlying)()=0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "fork");
    }
    pid_t returnval = (*underlying)();
    if(returnval==0) {
        getcon(&con);
        sprintf(buf, "fork %s %ld", context_type_get(context_new(con)), (long)getpid());
        freecon(con);
        rwfm_process(buf);
    }

    return returnval;
}

/*
int sigreturn(unsigned long __unused){
    char buf[50];
    int (*underlying)(unsigned long) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "sigreturn");
    }
    printf("\n### sigreturn\n");
    sprintf(buf, "exit_group %ld %ld", (long)getuid(), (long)getpid());
    //rwfm_process(buf);
    return (*underlying)(__unused);
}

int creat64(const char *pathname, mode_t mode){
    int newfd=0;
    char buf[1024];
    struct stat64 sb;
    static int (*underlying)(const char *pathname, mode_t mode) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "creat64");
    }
    printf("\n### creat64");
    newfd = (*underlying)(pathname, mode);
    if(newfd!=-1){
        stat64(pathname, &sb);
        sprintf(buf, "creat64 %ld %ld %ld %ld",
                (long)getuid(), (long)getpid(),
                (long)sb.st_dev, (long)sb.st_ino);
        if(!rwfm_process(buf))
            return -1;
    }
    return newfd;
}

int open(const char *pathname, int flags, mode_t mode) {
    static int (*underlying)(const char *pathname, int flags) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "open");
    }
    printf("\n### open with mode.");
    if(flags & O_CREAT)
        printf("\nCREAT\n");
    return (*underlying)(pathname, flags);
}

int execve(const char *filename, char *const argv[], char *const envp[]){
    char buf[50];
    static int (*underlying)(const char *, char * const*, char * const*)=0;
    printf("\n### execve\n");
    if (!underlying) {
        underlying = dlsym(get_libc(), "execve");
    }
    return (*underlying)(filename, argv, envp);
}

int chdir(const char *pathname) {
    static int (*underlying)(const char *pathname) = 0;
    if (!underlying) {
        underlying = dlsym(get_libc(), "chdir");
    }
    printf("\n### chdir\n");
    return (*underlying)(pathname);
}

int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...){
    static int (*underlying)(int(*)(void *), void *, int, void *, ...) = 0;
    printf("\n### clone\n");
    if (!underlying) {
        underlying = dlsym(get_libc(), "clone");
    }
    va_list ap;
    va_start (ap, arg);
    return (*underlying)(fn, child_stack, flags, arg, ap);
}
*/

