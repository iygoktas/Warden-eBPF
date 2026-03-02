#include <uapi/linux/ptrace.h>
#include <linux/limits.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_probe_read_user_str(&event.fname, sizeof(event.fname), args->filename);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}