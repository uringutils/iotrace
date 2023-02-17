#include "iotrace/probe.h"
#include <stdio.h>

#include "iotrace/iotrace.h"

const struct io_uring_op_desc io_uring_ops_desc[] = {
	[IO_RING_OP_NOP] = { .name = "NOP" },
	[IO_RING_OP_READV] = { .name = "READV" },
	[IO_RING_OP_WRITEV] = { .name = "WRITEV" },
	[IO_RING_OP_FSYNC] = { .name = "FSYNC" },
	[IO_RING_OP_READ_FIXED] = { .name = "READ_FIXED" },
	[IO_RING_OP_WRITE_FIXED] = { .name = "WRITE_FIXED" },
	[IO_RING_OP_POLL_ADD] = { .name = "POLL_ADD" },
	[IO_RING_OP_POLL_REMOVE] = { .name = "POLL_REMOVE" },
	[IO_RING_OP_SYNC_FILE_RANGE] = { .name = "SYNC_FILE_RANGE" },
	[IO_RING_OP_SENDMSG] = { .name = "SENDMSG" },
	[IO_RING_OP_RECVMSG] = { .name = "RECVMSG" },
	[IO_RING_OP_TIMEOUT] = { .name = "TIMEOUT" },
	[IO_RING_OP_TIMEOUT_REMOVE] = { .name = "TIMEOUT_REMOVE" },
	[IO_RING_OP_ACCEPT] = { .name = "ACCEPT" },
	[IO_RING_OP_ASYNC_CANCEL] = { .name = "ASYNC_CANCEL" },
	[IO_RING_OP_LINK_TIMEOUT] = { .name = "LINK_TIMEOUT" },
	[IO_RING_OP_CONNECT] = { .name = "CONNECT" },
	[IO_RING_OP_FALLOCATE] = { .name = "FALLOCATE" },
	[IO_RING_OP_OPENAT] = { .name = "OPENAT" },
	[IO_RING_OP_CLOSE] = { .name = "CLOSE" },
	[IO_RING_OP_FILES_UPDATE] = { .name = "FILES_UPDATE" },
	[IO_RING_OP_STATX] = { .name = "STATX" },
	[IO_RING_OP_READ] = { .name = "READ" },
	[IO_RING_OP_WRITE] = { .name = "WRITE" },
	[IO_RING_OP_FADVISE] = { .name = "FADVISE" },
	[IO_RING_OP_MADVISE] = { .name = "MADVISE" },
	[IO_RING_OP_SEND] = { .name = "SEND" },
	[IO_RING_OP_RECV] = { .name = "RECV" },
	[IO_RING_OP_OPENAT2] = { .name = "OPENAT2" },
	[IO_RING_OP_EPOLL_CTL] = { .name = "EPOLL_CTL" },
	[IO_RING_OP_SPLICE] = { .name = "SPLICE" },
	[IO_RING_OP_PROVIDE_BUFFERS] = { .name = "PROVIDE_BUFFERS" },
	[IO_RING_OP_REMOVE_BUFFERS] = { .name = "REMOVE_BUFFERS" },
	[IO_RING_OP_TEE] = { .name = "TEE" },
	[IO_RING_OP_SHUTDOWN] = { .name = "SHUTDOWN" },
	[IO_RING_OP_RENAMEAT] = { .name = "RENAMEAT" },
	[IO_RING_OP_UNLINKAT] = { .name = "UNLINKAT" },
	[IO_RING_OP_MKDIRAT] = { .name = "MKDIRAT" },
	[IO_RING_OP_SYMLINKAT] = { .name = "SYMLINKAT" },
	[IO_RING_OP_LINKAT] = { .name = "LINKAT" },
	[IO_RING_OP_MSG_RING] = { .name = "MSG_RING" },
	[IO_RING_OP_FSETXATTR] = { .name = "FSETXATTR" },
	[IO_RING_OP_SETXATTR] = { .name = "SETXATTR" },
	[IO_RING_OP_FGETXATTR] = { .name = "FGETXATTR" },
	[IO_RING_OP_GETXATTR] = { .name = "GETXATTR" },
	[IO_RING_OP_SOCKET] = { .name = "SOCKET" },
	[IO_RING_OP_URING_CMD] = { .name = "URING_CMD" },
	[IO_RING_OP_SEND_ZC] = { .name = "SEND_ZC" },
	[IO_RING_OP_SENDMSG_ZC] = { .name = "SENDMSG_ZC" },
	[IO_RING_OP_LAST] = { .name = "LAST" }
};

char *get_opcode_str(enum io_uring_ops opcode)
{
	if (opcode < IO_RING_OP_LAST)
		return io_uring_ops_desc[opcode].name;
	return "INVALID";
}

void print_event(const struct message *msg)
{
	char txt[256] = { 0 };

	snprintf(txt, 256, "opcode: %s, fd: %d, user_data: %p group_id: %x",
		 get_opcode_str(msg->opcode), msg->fd, (void *)msg->user_data,
		 msg->buf_index);

	if (msg->type == IO_URING_SUBMIT_SQE) {
		printf("SUBMIT_EVENT: %s\n", txt);
	} else {
		printf("COMPLETE_EVENT: %s\n", txt);
	}
}
