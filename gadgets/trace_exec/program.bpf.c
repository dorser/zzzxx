// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

#define ARGSIZE 128
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define BASE_EVENT_SIZE (size_t)(&((struct event *)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct event
{
  gadget_timestamp timestamp_raw;

  gadget_comm comm[TASK_COMM_LEN];
  gadget_pid pid;
  gadget_tid tid;
  gadget_uid uid;
  gadget_gid gid;

  gadget_pcomm pcomm[TASK_COMM_LEN];
  gadget_ppid ppid;
  gadget_errno error_raw;
  int args_count;
  unsigned int args_size;
  char cwd[MAX_STRING_SIZE];
  char args[FULL_MAX_ARGS_ARR];
};

static const struct event empty_event = {};

// man clone(2):
//   If any of the threads in a thread group performs an
//   execve(2), then all threads other than the thread group
//   leader are terminated, and the new program is executed in
//   the thread group leader.
//
// sys_enter_execve might be called from a thread and the corresponding
// sys_exit_execve will be called from the thread group leader in case of
// execve success, or from the same thread in case of execve failure.
//
// Moreover, checking ctx->ret == 0 is not a reliable way to distinguish
// successful execve from failed execve because seccomp can change ctx->ret.
//
// Therefore, use two different tracepoints to handle the map cleanup:
// - tracepoint/sched/sched_process_exec is called after a successful execve
// - tracepoint/syscalls/sys_exit_execve is always called
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct event);
} execs SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(exec, events, event);

static __always_inline int enter_execve(const char *pathname, const char **args)
{
  u64 id;
  pid_t pid, tgid;
  struct event *event;
  struct task_struct *task;
  unsigned int ret;
  const char *argp;
  int i;
  u64 uid_gid = bpf_get_current_uid_gid();
  u32 uid = (u32)uid_gid;
  u32 gid = (u32)(uid_gid >> 32);

  task = (struct task_struct *)bpf_get_current_task();

  id = bpf_get_current_pid_tgid();
  pid = (pid_t)id;
  tgid = id >> 32;

  if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
    return 0;

  event = bpf_map_lookup_elem(&execs, &pid);
  if (!event)
    return 0;

  event->timestamp_raw = bpf_ktime_get_boot_ns();
  event->pid = tgid;
  event->tid = pid;
  event->uid = uid;
  event->gid = gid;
  event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
  event->args_count = 0;
  event->args_size = 0;

  struct fs_struct *fs = BPF_CORE_READ(task, fs);
  char *cwd = get_path_str(&fs->pwd);
  bpf_probe_read_kernel_str(event->cwd, MAX_STRING_SIZE, cwd);

  ret = bpf_probe_read_user_str(event->args, ARGSIZE, pathname);
  if (ret <= ARGSIZE)
  {
    event->args_size += ret;
  }
  else
  {
    /* write an empty string */
    event->args[0] = '\0';
    event->args_size++;
  }

  event->args_count++;
#pragma unroll
  for (i = 1; i < TOTAL_MAX_ARGS && i < DEFAULT_MAXARGS; i++)
  {
    bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
    if (!argp)
      return 0;

    if (event->args_size > LAST_ARG)
      return 0;

    ret = bpf_probe_read_user_str(&event->args[event->args_size],
                                  ARGSIZE, argp);
    if (ret > ARGSIZE)
      return 0;

    event->args_count++;
    event->args_size += ret;
  }
  /* try to read one more argument to check if there is one */
  bpf_probe_read_user(&argp, sizeof(argp), &args[DEFAULT_MAXARGS]);
  if (!argp)
    return 0;

  /* pointer to max_args+1 isn't null, asume we have more arguments */
  event->args_count++;
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int ig_execve_e(struct syscall_trace_enter *ctx)
{
  const char *pathname = (const char *)ctx->args[0];
  const char **args = (const char **)(ctx->args[1]);
  return enter_execve(pathname, args);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int ig_execveat_e(struct syscall_trace_enter *ctx)
{
  const char *pathname = (const char *)ctx->args[1];
  const char **args = (const char **)(ctx->args[2]);
  return enter_execve(pathname, args);
}

// tracepoint/sched/sched_process_exec is called after a successful execve
SEC("tracepoint/sched/sched_process_exec")
int ig_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
  u32 execs_lookup_key = ctx->old_pid;
  struct event *event;
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct task_struct *parent = BPF_CORE_READ(task, real_parent);

  event = bpf_map_lookup_elem(&execs, &execs_lookup_key);
  if (!event)
    return 0;

  event->error_raw = 0;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));
  if (parent != NULL)
  {
    bpf_probe_read_kernel(&event->pcomm, sizeof(event->pcomm),
                          parent->comm);
  }

  size_t len = EVENT_SIZE(event);
  if (len <= sizeof(*event))
    gadget_output_buf(ctx, &events, event, len);

  bpf_map_delete_elem(&execs, &execs_lookup_key);

  return 0;
}

// We use syscalls/sys_exit_execve only to trace failed execve
// This program is needed regardless of ignore_failed
static __always_inline int exit_execve(void *ctx, int retval)
{
  u32 pid = (u32)bpf_get_current_pid_tgid();
  struct event *event;
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct task_struct *parent = BPF_CORE_READ(task, real_parent);

  // If the execve was successful, sched/sched_process_exec handled the event
  // already and deleted the entry. So if we find the entry, it means the
  // the execve failed.
  event = bpf_map_lookup_elem(&execs, &pid);
  if (!event)
    return 0;

  goto cleanup;

  event->error_raw = -retval;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  if (parent != NULL)
  {
    bpf_probe_read_kernel(&event->pcomm, sizeof(event->pcomm),
                          parent->comm);
  }

  size_t len = EVENT_SIZE(event);
  if (len <= sizeof(*event))
    gadget_output_buf(ctx, &events, event, len);
cleanup:
  bpf_map_delete_elem(&execs, &pid);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct syscall_trace_exit *ctx)
{
  return exit_execve(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int ig_execveat_x(struct syscall_trace_exit *ctx)
{
  return exit_execve(ctx, ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
