/* Code for loading Linux executables.  Mostly linux kernel code.  */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "loader.h"

#define NGROUPS 32

/* ??? This should really be somewhere else.  */
abi_long memcpy_to_target(abi_ulong dest, const void *src, unsigned long len)
{
    void *host_ptr;

    host_ptr = lock_user(VERIFY_WRITE, dest, len, 0);
    if (!host_ptr) {
        return -TARGET_EFAULT;
    }
    memcpy(host_ptr, src, len);
    unlock_user(host_ptr, dest, 1);
    return 0;
}

static int count(char **vec)
{
    int i;

    for (i = 0; *vec; i++) {
        vec++;
    }
    return i;
}

static int prepare_binprm(struct linux_binprm *bprm)
{
    struct stat st;
    int mode;
    int retval;

    if (fstat(bprm->fd, &st) < 0) {
        return -errno;
    }

    mode = st.st_mode;
    if (!S_ISREG(mode)) {   /* Must be regular file */
        return -EACCES;
    }
    if (!(mode & 0111)) {   /* Must have at least one execute bit set */
        return -EACCES;
    }

    bprm->e_uid = geteuid();
    bprm->e_gid = getegid();

    /* Set-uid? */
    if (mode & S_ISUID) {
        bprm->e_uid = st.st_uid;
    }

    /* Set-gid? */
    /*
     * If setgid is set but no group execute bit then this
     * is a candidate for mandatory locking, not a setgid
     * executable.
     */
    if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
        bprm->e_gid = st.st_gid;
    }

    retval = read(bprm->fd, bprm->buf, BPRM_BUF_SIZE);
    if (retval < 0) {
        perror("prepare_binprm");
        exit(-1);
    }
    if (retval < BPRM_BUF_SIZE) {
        /* Make sure the rest of the loader won't read garbage.  */
        memset(bprm->buf + retval, 0, BPRM_BUF_SIZE - retval);
    }
    return retval;
}

/* Construct the envp and argv tables on the target stack.  */
abi_ulong loader_build_argptr(int envc, int argc, abi_ulong sp,
                              abi_ulong stringp, int push_ptr)
{
    TaskState *ts = (TaskState *)thread_cpu->opaque;
    int n = sizeof(abi_ulong);
    abi_ulong envp;
    abi_ulong argv;

    sp -= (envc + 1) * n;
    envp = sp;
    sp -= (argc + 1) * n;
    argv = sp;
    if (push_ptr) {
        /* FIXME - handle put_user() failures */
        sp -= n;
        put_user_ual(envp, sp);
        sp -= n;
        put_user_ual(argv, sp);
    }
    sp -= n;
    /* FIXME - handle put_user() failures */
    put_user_ual(argc, sp);
    ts->info->arg_start = stringp;
    while (argc-- > 0) {
        /* FIXME - handle put_user() failures */
        put_user_ual(stringp, argv);
        argv += n;
        stringp += target_strlen(stringp) + 1;
    }
    ts->info->arg_end = stringp;
    /* FIXME - handle put_user() failures */
    put_user_ual(0, argv);
    while (envc-- > 0) {
        /* FIXME - handle put_user() failures */
        put_user_ual(stringp, envp);
        envp += n;
        stringp += target_strlen(stringp) + 1;
    }
    /* FIXME - handle put_user() failures */
    put_user_ual(0, envp);

    return sp;
}

int loader_exec(int fdexec, const char *filename, char **argv, char **envp,
                struct target_pt_regs *regs, struct image_info *infop,
                struct linux_binprm *bprm)
{
    int retval;

    bprm->fd = fdexec;
    bprm->filename = (char *)filename;
    bprm->argc = count(argv);
    bprm->argv = argv;
    bprm->envc = count(envp);
    bprm->envp = envp;

    retval = prepare_binprm(bprm);

    if (retval >= 0) {
        if (bprm->buf[0] == 0x7f
                && bprm->buf[1] == 'E'
                && bprm->buf[2] == 'L'
                && bprm->buf[3] == 'F') {
            retval = load_elf_binary(bprm, infop);
#if defined(TARGET_HAS_BFLT)
        } else if (bprm->buf[0] == 'b'
                && bprm->buf[1] == 'F'
                && bprm->buf[2] == 'L'
                && bprm->buf[3] == 'T') {
            retval = load_flt_binary(bprm, infop);
#endif
        } else {
            // No shebang, try to execute with /bin/sh
            const char *shell = "/bin/sh";
            int shell_fd = open(shell, O_RDONLY);
            if (shell_fd >= 0) {
                struct linux_binprm shell_bprm;
                struct image_info shell_info;
                char *shell_argv[3];
                
                // Initialize shell arguments
                shell_argv[0] = (char *)shell;
                shell_argv[1] = bprm->filename;
                shell_argv[2] = NULL;
                
                // Initialize shell_bprm
                memset(&shell_bprm, 0, sizeof(struct linux_binprm));
                shell_bprm.fd = shell_fd;
                shell_bprm.filename = (char *)shell;
                shell_bprm.argc = 2;
                shell_bprm.argv = shell_argv;
                shell_bprm.envc = bprm->envc;
                shell_bprm.envp = bprm->envp;
                
                // Initialize shell_info
                memset(&shell_info, 0, sizeof(struct image_info));
                
                // Try to load the shell
                int shell_retval = prepare_binprm(&shell_bprm);
                if (shell_retval >= 0) {
                    if (shell_bprm.buf[0] == 0x7f
                            && shell_bprm.buf[1] == 'E'
                            && shell_bprm.buf[2] == 'L'
                            && shell_bprm.buf[3] == 'F') {
                        shell_retval = load_elf_binary(&shell_bprm, &shell_info);
                        if (shell_retval >= 0) {
                            // Success, copy shell_info to infop
                            memcpy(infop, &shell_info, sizeof(struct image_info));
                            // Update bprm to point to shell's bprm
                            *bprm = shell_bprm;
                            // Initialize registers for shell
                            do_init_thread(regs, infop);
                            close(shell_fd);
                            return shell_retval;
                        }
                    }
                }
                close(shell_fd);
            }
            return -ENOEXEC;
        }
    }

    if (retval >= 0) {
        /* success.  Initialize important registers */
        do_init_thread(regs, infop);
        return retval;
    }

    return retval;
}
