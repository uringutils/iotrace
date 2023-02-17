#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"

#include "../include/iotrace/probe.h"

char __license[] SEC("license") = "Dual MIT/GPL";

const volatile pid_t tracee_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} messages SEC(".maps");

SEC("tracepoint/io_uring/io_uring_complete")
int io_uring_complete(struct trace_event_raw_io_uring_complete *event)
{
	u64 pid;
	struct message *msg;
	struct io_kiocb iocb = { 0 };

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != tracee_pid)
		return 0;

	if (bpf_probe_read_kernel(&iocb, sizeof(struct io_kiocb), event->req) <
	    0)
		return 0;

	msg = bpf_ringbuf_reserve(&messages, sizeof(struct message), 0);
	if (!msg)
		return 0;
	msg->type = IO_URING_COMPLETE;
	msg->opcode = iocb.opcode;
	msg->fd = 0;
	msg->user_data = event->user_data;
	msg->buf_index = iocb.buf_index;

	bpf_ringbuf_submit(msg, 0);
	return 0;
}

SEC("tracepoint/io_uring/io_uring_submit_sqe")
int io_uring_submit_sqe(struct trace_event_raw_io_uring_submit_sqe *event)
{
	u64 pid;
	struct message *msg;
	struct io_kiocb iocb = { 0 };

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != tracee_pid)
		return 0;

	if (bpf_probe_read_kernel(&iocb, sizeof(struct io_kiocb), event->req) <
	    0)
		return 0;

	msg = bpf_ringbuf_reserve(&messages, sizeof(struct message), 0);
	if (!msg)
		return 0;

	msg->type = IO_URING_SUBMIT_SQE;
	msg->opcode = event->opcode;
	msg->fd = iocb.cqe.fd;
	msg->user_data = event->user_data;
	msg->buf_index = BPF_CORE_READ(iocb.ctx, sq_sqes, opcode);

	bpf_ringbuf_submit(msg, 0);
	return 0;
}
