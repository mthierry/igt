/*
 * Copyright © 2016 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *    Arun Siluvery <arun.siluvery@linux.intel.com>
 *    Michel Thierry <michel.thierry@intel.com>
 */

#include "igt.h"
#include "igt_sysfs.h"

#include <fcntl.h>

int fd, devid;

static drm_intel_bufmgr *bufmgr;
struct intel_batchbuffer *batch;
static unsigned int num_engines;
static unsigned int full_gpu_reset_count;
static int sysfs = -1;

const struct intel_execution_engine *e;

#define engine_flag(x)	(1UL << (x))

enum hang_batch_type {
	NO_HANG,
	HANG_USING_SEMAPHORE_WAIT,
	HANG_USING_LOOP,
};

static const struct target_engines {
	const int id;
	const char *name;
} engines[] = {
	{ I915_EXEC_RENDER, "Render" },
	{ I915_EXEC_BSD, "Media" },
	{ I915_EXEC_BLT, "Blitter"},
	{ I915_EXEC_VEBOX, "Vebox"},
	/* vcs2 is not yet exported to userspace */
};

uint32_t good_batch[2] = {MI_NOOP, MI_BATCH_BUFFER_END};
uint32_t bad_batch[] = {
	0x0E008002,	/* MI_SEMAPHORE_WAIT */
	/* semaphore address data */
	0xffffffff,
	0x0,
	0x0,
	0x0, /* MI_NOOP */
	0x0, /* MI_NOOP */
	0x0, /* MI_NOOP */
	MI_BATCH_BUFFER_END,
};

#define MAX_BATCH_SIZE 4096
static drm_intel_bo *create_batch(unsigned int size, int cause_hang)
{
	drm_intel_bo *bo;
	uint32_t *buf;

	bo = drm_intel_bo_alloc(bufmgr, "bo", size, size);
	igt_assert(bo);

	drm_intel_bo_map(bo, 1);
	buf = bo->virtual;
	igt_assert(buf);

	if (cause_hang)
		memcpy(buf, bad_batch, ARRAY_SIZE(bad_batch));
	else
		memcpy(buf, good_batch, ARRAY_SIZE(good_batch));

	drm_intel_bo_unmap(bo);
	return bo;
}

static uint32_t submit_batch(int drmfd, int engine_id, unsigned int flags,
			     enum hang_batch_type batch_type, bool wait)
{
	struct drm_i915_gem_execbuffer2 execbuf;
	struct drm_i915_gem_exec_object2 exec;
	struct drm_i915_gem_relocation_entry reloc;
	uint32_t *buf;
	uint32_t b[8];
	int buf_size, len;
	int ret = 0;

	buf_size = 0;
	memset(b, 0, sizeof(b));
	memset(&reloc, 0, sizeof(reloc));
	memset(&exec, 0, sizeof(exec));
	memset(&execbuf, 0, sizeof(execbuf));

	exec.handle = gem_create(drmfd, 4096);
	switch(batch_type) {
	case NO_HANG:
		buf_size = sizeof(good_batch);
		buf = good_batch;
		igt_info("NO_HANG\n");
		break;
	case HANG_USING_SEMAPHORE_WAIT:
		buf_size = sizeof(bad_batch);
		buf = bad_batch;
		igt_info("HANG_USING_SEMAPHORE_WAIT\n");
		break;
	case HANG_USING_LOOP:
		len = 2;
		exec.relocation_count = 1;
		exec.relocs_ptr = (uintptr_t)&reloc;

		if (intel_gen(devid) >= 8)
			len++;
		b[0] = MI_BATCH_BUFFER_START | (len - 2);
		b[len] = MI_BATCH_BUFFER_END;
		b[len+1] = MI_NOOP;

		reloc.offset = 4;
		reloc.target_handle = exec.handle;
		reloc.read_domains = I915_GEM_DOMAIN_COMMAND;

		buf = b;
		buf_size = sizeof(b);
		igt_info("HANG_USING_LOOP\n");
		break;
	default:
		igt_assert(1);
	}

	gem_write(drmfd, exec.handle, 0, buf, buf_size);

	execbuf.buffers_ptr = (uintptr_t)&exec;
	execbuf.buffer_count = 1;
	execbuf.batch_len = buf_size;
	execbuf.flags = (engine_id | flags);
	i915_execbuffer2_set_context_id(execbuf, 0);

	ret = drmIoctl(drmfd, DRM_IOCTL_I915_GEM_EXECBUFFER2, &execbuf);
	igt_assert(ret == 0);

	if (wait)
		gem_sync(drmfd, exec.handle);

	return exec.handle;
}

static int check_dfs_reset_info(void)
{
	FILE *file;
	int fdx, ret;

	fdx = igt_debugfs_open(fd, "i915_reset_info", O_RDONLY);
	file = fdopen(fdx, "r");
	igt_require(file);
	igt_assert_eq(fscanf(file, "full gpu reset = %i", &ret), 1);
	fclose(file);

	return ret;
}

static void wait_rendering(drm_intel_bo *bo, unsigned int delay)
{
	/*
	 * Wait for completion - caution drm_intel_bo_wait_rendering
	 * can return as soon as a hang is detected but *before*
	 * recovery work has completed so wait a while after
	 * the wait rendering call returns to ensure we get correct
	 * results
	 */

	igt_info("Waiting for buffer for max %d sec\n", delay);
	igt_assert(delay);
	drm_intel_bo_wait_rendering(bo);
	sleep(delay);
}

static uint32_t hang_engine(unsigned int engine, unsigned int flags, bool wait)
{
	return submit_batch(fd, engine, flags, (random() % 2) + 1, wait);
}

static uint32_t no_hang(unsigned int engine, unsigned int flags, bool wait)
{
	return submit_batch(fd, engine, flags, NO_HANG, wait);
}

static uint64_t submit_hang(int _fd, unsigned engine_id, bool media_reset)
{
	igt_hang_t hang;
	uint32_t ctx = 0;
	uint32_t flags = HANG_ALLOW_CAPTURE;
	uint64_t offset;

	if (media_reset) {
		flags |= HANG_USE_WATCHDOG;

		if (engine_id == I915_EXEC_RENDER)
			ctx = gem_context_create(_fd);
	}

	hang = igt_hang_ctx(_fd, ctx, engine_id, flags, &offset);
	igt_post_hang_ring(_fd, hang);

	return offset;
}

/* don't run tests in bsd1 twice */
static bool ignore_single_bsd_engine(unsigned engine_id)
{
	if (gem_has_bsd2(fd) && engine_id == I915_EXEC_BSD)
		return true;

	return false;
}

/* copied from drv_hangman.c */
static void assert_entry(const char *s, bool expect)
{
	char *error;

	error = igt_sysfs_get(sysfs, "error");
	igt_assert(error);

	igt_assert_f(!!strcasecmp(error, s) != expect,
		     "contents of error: '%s' (expected %s '%s')\n",
		     error, expect ? "": "not", s);

	free(error);
}

static void clear_error_state(void)
{
	igt_sysfs_set(sysfs, "error", " ");
}

static void assert_error_state_clear(void)
{
	assert_entry("no error state collected", true);
}

static void assert_error_state_collected(void)
{
	assert_entry("no error state collected", false);
}

static void test_engine(unsigned engine_id, bool media_reset)
{
	igt_skip_on_f(ignore_single_bsd_engine(engine_id),
		      "platform with multiple bsd engines, skipping\n");
	igt_skip_on_f(media_reset && engine_id == I915_EXEC_BLT,
		      "no official watchdog support in BLT engine\n");

	gem_require_ring(fd, engine_id);
	full_gpu_reset_count = check_dfs_reset_info();
	clear_error_state();
	assert_error_state_clear();

	submit_hang(fd, engine_id, media_reset);

	if (media_reset)
		assert_error_state_clear();
	else
		assert_error_state_collected();
	igt_assert_eq(full_gpu_reset_count, check_dfs_reset_info());
}

static void test_engine_parallel(unsigned nchildren, unsigned engine_id)
{
	igt_skip_on_f(ignore_single_bsd_engine(engine_id),
		      "platform with multiple bsd engines, skipping\n");

	gem_require_ring(fd, engine_id);
	full_gpu_reset_count = check_dfs_reset_info();
	clear_error_state();
	assert_error_state_clear();

	igt_fork(child, nchildren) {
		submit_hang(fd, engine_id, 0);
	}

	igt_waitchildren();
	assert_error_state_collected();
	igt_assert_eq(full_gpu_reset_count, check_dfs_reset_info());
}

static void test_all_engines(void)
{
	igt_info("Test Engine reset for all engines \n");
	full_gpu_reset_count = check_dfs_reset_info();
	clear_error_state();
	assert_error_state_clear();

	for (e = intel_execution_engines; e->name; e++) {
		if (e->exec_id == 0 ||
		    ignore_single_bsd_engine(e->exec_id | e->flags) ||
		    !gem_has_ring(fd, e->exec_id | e->flags))
			continue;

		igt_info("Reset %s engine\n", e->name);
		hang_engine(e->exec_id | e->flags, 0, true);
		sleep(2);
	}

	assert_error_state_collected();
	igt_assert_eq(full_gpu_reset_count, check_dfs_reset_info());
}

static void test_all_engines_parallel(void)
{
	igt_info("Test Engine reset for all engines in parallel\n");
	full_gpu_reset_count = check_dfs_reset_info();
	clear_error_state();
	assert_error_state_clear();

	for (e = intel_execution_engines; e->name; e++) {
		if (e->exec_id == 0 ||
		    ignore_single_bsd_engine(e->exec_id | e->flags) ||
		    !gem_has_ring(fd, e->exec_id | e->flags))
			continue;

		igt_info("Reset %s engine\n", e->name);
		igt_fork(child, 2) {
			test_engine(e->exec_id | e->flags, 0);
		}
	}

	igt_waitchildren();
	assert_error_state_collected();
	igt_assert_eq(full_gpu_reset_count, check_dfs_reset_info());
}

/*
 * Insert a bad batch buffer to each of the engines specified in "mask".
 * No explicit dependencies are created between the batch buffers.
 */
static void test_engine_combinations(unsigned int flags)
{
	int i;
	uint32_t mask;
	struct timeval start, end;
	uint32_t hang_batches[num_engines];
	uint32_t normal_batch[num_engines];

	igt_info("Ring hang test with different combinations\n");
	gettimeofday(&start, NULL);
	full_gpu_reset_count = check_dfs_reset_info();
	clear_error_state();
	assert_error_state_clear();

	for (mask = 1; mask < (0x1 << num_engines); mask++) {
		igt_info("Rings combination: 0x%x\n", mask);

		/* submit the buffers */
		for (i = 0; i < num_engines; i++) {
			if (mask & engine_flag(i)) {
				igt_info("%s, ", engines[i].name);
				hang_batches[i] = hang_engine((I915_EXEC_RENDER + i),
							  flags,
							  false);
				normal_batch[i] = no_hang((I915_EXEC_RENDER + i),
							  flags,
							  false);
			}
		}
		igt_info("\n");

		/* Wait for completion */
		for (i = 0; i < num_engines; i++) {
			if (mask & engine_flag(i)) {
				gem_sync(fd, hang_batches[i]);
				gem_sync(fd, normal_batch[i]);
			}
		}
	}

	assert_error_state_collected();
	igt_assert_eq(full_gpu_reset_count, check_dfs_reset_info());
	gettimeofday(&end, NULL);
	igt_info("Time elapsed: %ld sec\n", (end.tv_sec - start.tv_sec));
}

/*
 * Helper function to make batch 'a' dependent on batch 'b' by emitting
 * a relocation beyond the MI_BATCH_BUFFER_END. This is a fake
 * dependency, but the kernel will treat it as a real dependency.
 */
static void associate_batch(drm_intel_bo *a, drm_intel_bo *b)
{
	int rc;
	unsigned *buf;

	drm_intel_bo_map(a, 1);
	buf = a->virtual;
	buf[4] = b->offset;

	rc = drm_intel_bo_emit_reloc(a,
				(unsigned char*)(&buf[4]) -
				(unsigned char*)(a->virtual),
				a, 0,
				I915_GEM_DOMAIN_RENDER, 0);

	igt_assert(rc == 0);
	drm_intel_bo_unmap(a);
}

static void test_engine_dependencies(void)
{
	drm_intel_bo *cmd_bo[num_engines];
	unsigned mask;
	unsigned engine;
	unsigned i;
	unsigned exec_flags;
	int ret;

	full_gpu_reset_count = check_dfs_reset_info();
	clear_error_state();
	assert_error_state_clear();

	for (engine = 0; engine < num_engines; engine++) {
		printf("Primary (%s)\n", engines[engine].name);
		for (mask = 1; mask < (0x1 << num_engines); mask++) {
			/* Skip if the mask contains the engine under test */
			if (mask & engine_flag(engine))
				continue;

			printf("Mask: 0x%08X\n", mask);
			cmd_bo[engine] = create_batch(MAX_BATCH_SIZE, 1);
			igt_assert(cmd_bo[engine]);

			/* Prepare dependents */
			for (i = 0; i < num_engines; i++) {
				if (mask & engine_flag(i)) {
					cmd_bo[i] = create_batch(MAX_BATCH_SIZE, 0);
					igt_assert(cmd_bo[i]);
					printf("\tDependent (%s)\n", engines[i].name);

					associate_batch(cmd_bo[i],
						cmd_bo[engine]);
				}
			}

			/* Submit the hanging buffer */
			ret = drm_intel_bo_mrb_exec(cmd_bo[engine],
					MAX_BATCH_SIZE,
					NULL, 0, 0, exec_flags | (engine + 1));
			igt_assert(ret == 0);

			usleep(500);

			/* Submit the dependants */
			for (i = 0; i < num_engines; i++) {
				if (mask & engine_flag(i)) {
					drm_intel_bo_mrb_exec(cmd_bo[i],
						MAX_BATCH_SIZE,
						NULL, 0, 0, exec_flags | (i + 1));
				}
			}

			/* Wait for completion of dependants */
			for (i = 0; i < num_engines; i++) {
				if (mask & engine_flag(i))
					wait_rendering(cmd_bo[i], 5);
			}

			for (i = 0; i < num_engines; i++) {
				if (mask & engine_flag(i)) {
					drm_intel_bo_unreference(cmd_bo[i]);
					cmd_bo[i] = NULL;
				}
			}
		}
	}

	assert_error_state_collected();
	igt_assert_eq(full_gpu_reset_count, check_dfs_reset_info());
}

igt_main
{
	igt_skip_on_simulation();

	igt_fixture {
		fd = drm_open_driver(DRIVER_INTEL);
		devid = intel_get_drm_devid(fd);
		sysfs = igt_sysfs_open(fd, NULL);
		igt_assert(sysfs != -1);

		/* Be sure engine reset is enabled */
		igt_assert(igt_sysfs_set_parameter
			   (fd, "reset", "%d", 2 /* engine reset */));
		igt_skip_on_f(gem_gpu_reset_type(fd) < 2,
			      "platform without reset-engine, skipping\n");

		/* Set up other stuff shared by all tests. */
		bufmgr = drm_intel_bufmgr_gem_init(fd, 4096);
	        drm_intel_bufmgr_gem_enable_reuse(bufmgr);
	        batch = intel_batchbuffer_alloc(bufmgr, devid);

		num_engines = 1; /* render is always available */
		if (gem_has_bsd(fd))
			num_engines++;

		if (gem_has_blt(fd))
			num_engines++;

		if (gem_has_vebox(fd))
			num_engines++;
	}

	for (e = intel_execution_engines; e->name; e++) {
		if (e->exec_id == 0)
			continue;
		if (ignore_single_bsd_engine(e->exec_id | e->flags))
			continue;
		igt_subtest_f("%s", e->name)
			test_engine(e->exec_id | e->flags, 0);
		// Note: watchdog not supported in blt engine
		igt_subtest_f("%s-watchdog", e->name)
			test_engine(e->exec_id | e->flags, 1);
	}

	for (e = intel_execution_engines; e->name; e++) {
		if (e->exec_id == 0)
			continue;
		if (ignore_single_bsd_engine(e->exec_id | e->flags))
			continue;
		igt_subtest_f("%s-parallel", e->name)
			test_engine_parallel(10, e->exec_id | e->flags);
	}

	igt_subtest("all-engines")
		test_all_engines();

	igt_subtest("all-engines-parallel")
		test_all_engines_parallel();

	igt_subtest("engine-combinations-no-deps")
		test_engine_combinations(0);

	igt_subtest("engine-with-deps")
		test_engine_dependencies();

	igt_fixture {
		intel_batchbuffer_free(batch);
		drm_intel_bufmgr_destroy(bufmgr);

		close(fd);
	}

	igt_exit();
}
