#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "iotrace/iotrace.h"
#include "probe.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct message *msg = data;

	print_event(msg);

	return 0;
}

int8_t trace_pid(int tracee_pid)
{
	struct ring_buffer *rb = NULL;
	struct probe_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = probe_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with the tracee pid */
	skel->rodata->tracee_pid = tracee_pid;

	/* Load & verify BPF programs */
	err = probe_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = probe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.messages), handle_event,
			      NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	probe_bpf__destroy(skel);

	return err < 0 ? -1 : 0;
}

int main(int argc, char **argv)
{
	int tracee_pid;
	if (argc != 2) {
		fprintf(stderr, "Usage: iotrace pid\n");
		return 2;
	}

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	tracee_pid = strtol(argv[1], NULL, 10);
	printf("Trying to trace pid %d\n", tracee_pid);
	return trace_pid(tracee_pid);
}
