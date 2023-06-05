/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef IOTRACE_H
#define IOTRACE_H

#include <stdint.h>
#include "probe.h"

void print_event(const struct message *msg);

#endif /* IOTRACE_H */
