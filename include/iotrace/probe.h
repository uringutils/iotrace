/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef PROBE_H
#define PROBE_H

enum event_type {
  IO_URING_COMPLETE,
  IO_URING_SUBMIT_SQE,
};

struct message {
  uint64_t user_data;
  uint8_t opcode;
  int res;
  enum event_type type;
};

#endif /* PROBE_H */
