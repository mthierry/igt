/*
 * Copyright © 2017 Intel Corporation
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
 */

#include "igt.h"
#include "igt_sysfs.h"

IGT_TEST_DESCRIPTION("Check hw watchdog interface and operation");

static void require_watchdog(int fd)
{
	struct local_i915_gem_context_param param;
        unsigned engines_threshold[MAX_ENGINES];

        memset(&param, 0, sizeof(param));
	param.context = 0;
	param.param = LOCAL_CONTEXT_PARAM_WATCHDOG;
	param.value = (uint64_t)&engines_threshold;;
	param.size = sizeof(engines_threshold);

	igt_require(__gem_context_get_param(fd, &param) == 0);
}

/* test for invalid api usage cases */
static void test_invalid(int fd)
{
        struct local_i915_gem_context_param param;
        unsigned ctx = 0;
	unsigned engines_threshold[MAX_ENGINES];

	memset(&param, 0, sizeof(param));
        memset(&engines_threshold, 0, sizeof(engines_threshold));

	param.context = ctx;
	param.value = (uint64_t)&engines_threshold;
	param.param = LOCAL_CONTEXT_PARAM_WATCHDOG;

	/* Get threshold array size */
	gem_context_get_param(fd, &param);
	igt_assert(param.size == sizeof(engines_threshold));

	/* invalid set - pass an unexpected array size, expecting EINVAL */
        param.value = (uint64_t)&engines_threshold;
        param.size = 1;
        igt_assert_eq(__gem_context_set_param(fd, &param), -EFAULT);

        /* invalid blitter - blt engine support is dubious, expecting EINVAL */
        engines_threshold[BCS] = 100;
        param.size = sizeof(engines_threshold);
        igt_assert_eq(__gem_context_set_param(fd, &param), -EINVAL);
        engines_threshold[BCS] = 0;

        /*
         * invalid overflow count - get EINVAL
         * a. Set a valid threshold value
         * b. Set a value that will overflow
         * c. Assert the error
         */
        engines_threshold[RCS] = 100;
        igt_assert_eq(__gem_context_set_param(fd, &param), 0);
        gem_context_get_param(fd, &param);
	igt_assert(engines_threshold[RCS] == 100);

        engines_threshold[RCS] = 0xffffffff;
        igt_assert_eq(__gem_context_set_param(fd, &param), -EINVAL);
}

/* test we can read back current thresholds */
static void test_read(int fd)
{
	struct local_i915_gem_context_param param;
	unsigned ctx = 0;
	unsigned engines_threshold[MAX_ENGINES];

	memset(&param, 0, sizeof(param));
	memset(&engines_threshold, 0, sizeof(engines_threshold));

	param.context = ctx;
	param.value = (uint64_t)&engines_threshold;
	param.size = 0xdeadbeef; // should be ignored
	param.param = LOCAL_CONTEXT_PARAM_WATCHDOG;

	/* Get threshold array size */
	gem_context_get_param(fd, &param);
	igt_assert(param.size == sizeof(engines_threshold));

	engines_threshold[RCS] = 11;
	engines_threshold[VCS] = 22;
	igt_assert_eq(__gem_context_set_param(fd, &param), 0);

	memset(&engines_threshold, 0, sizeof(engines_threshold));
	gem_context_get_param(fd, &param);
	igt_assert(engines_threshold[RCS] == 11);
	igt_assert(engines_threshold[VCS] == 22);
}

static void test_watchdog(int fd, unsigned ring, unsigned flags)
{

}

igt_main
{
        const struct intel_execution_engine *e;
        int i915 = -1;

        igt_skip_on_simulation();

	igt_fixture {
		i915 = drm_open_driver_master(DRIVER_INTEL);
		igt_require_gem(i915);
		igt_assert(igt_sysfs_set_parameter
			   (i915, "reset", "%d", 2 /* engine reset */));
		igt_skip_on_f(gem_gpu_reset_type(i915) < 2,
			      "platform without reset-engine, skipping\n");
                require_watchdog(i915);
	}

        igt_subtest_f("invalid")
                test_invalid(i915);

        igt_subtest_f("read")
                test_read(i915);

        for (e = intel_execution_engines; e->name; e++) {
                igt_subtest_group {
                        igt_fixture {
                                igt_require(gem_has_ring(i915, e->exec_id | e->flags));
                        }
                }

                igt_subtest_f("watchdog-%s", e->name);
                        test_watchdog(i915, e->exec_id | e->flags, 0);
        }

        igt_fixture {
                close(i915);
        }

        igt_exit();
}
