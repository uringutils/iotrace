#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "../include/iotrace/probe.h"

char __license[] SEC("license") = "Dual MIT/GPL";

const volatile pid_t tracee_pid = 0;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} messages SEC(".maps");

SEC("tracepoint/io_uring/io_uring_complete")
int io_uring_complete(struct trace_event_raw_io_uring_complete *event) {
  u64 pid;
  struct message *msg;
  struct io_uring_sqe req = {0};

  pid = bpf_get_current_pid_tgid() >> 32;
  if (pid != tracee_pid)
    return 0;

  msg = bpf_ringbuf_reserve(&messages, sizeof(struct message), 0);
  if (!msg)
    return 0;
  msg->res = event->res;
  msg->user_data = event->user_data;
  bpf_probe_read_user(&req, sizeof(struct io_uring_sqe), event->req);
  msg->opcode = req.opcode;
  msg->type = IO_URING_COMPLETE;

  bpf_ringbuf_submit(msg, 0);
  return 0;
}


SEC("tracepoint/io_uring/io_uring_submit_sqe")
int io_uring_submit_sqe(struct trace_event_raw_io_uring_submit_sqe *event) {
  u64 pid;
  struct message *msg;
  struct io_uring_sqe req = {0};

  pid = bpf_get_current_pid_tgid() >> 32;
  if (pid != tracee_pid)
    return 0;

  msg = bpf_ringbuf_reserve(&messages, sizeof(struct message), 0);
  if (!msg)
    return 0;
  msg->res = 0;
  msg->user_data = event->user_data;
  bpf_probe_read_user(&req, sizeof(struct io_uring_sqe), event->req);
  msg->opcode = req.opcode;
  msg->type = IO_URING_SUBMIT_SQE;

  bpf_ringbuf_submit(msg, 0);
  return 0;
}
