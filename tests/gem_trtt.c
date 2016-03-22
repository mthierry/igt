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
 *    Akash Goel <akash.goel@intel.com>
 *
 */

#include "igt.h"

#define BO_SIZE 4096
#define EXEC_OBJECT_PINNED	(1<<4)
#define EXEC_OBJECT_SUPPORTS_48B_ADDRESS (1<<3)

/* has_trtt_support
 * Finds if trtt hw is present
 * @fd DRM fd
 */
static bool has_trtt_support(int fd)
{
	int ret = __gem_context_require_param(fd, LOCAL_CONTEXT_PARAM_TRTT);

	return (ret == 0);
}

/* mmap_bo
 * helper for creating a CPU mmapping of the buffer
 * @fd - drm fd
 * @handle - handle of the buffer to mmap
 * @size: size of the buffer
 */
static void* mmap_bo(int fd, uint32_t handle, uint64_t size)
{
	uint32_t *ptr = gem_mmap__cpu(fd, handle, 0, size, PROT_READ);
	gem_set_domain(fd, handle, I915_GEM_DOMAIN_CPU, 0);
	return ptr;
}

/* emit_store_dword
 * populate batch buffer with MI_STORE_DWORD_IMM command
 * @fd: drm file descriptor
 * @cmd_buf: batch buffer
 * @dw_offset: write offset in batch buffer
 * @vaddr: destination Virtual address
 * @data: u32 data to be stored at destination
 */
static int emit_store_dword(int fd, uint32_t *cmd_buf, uint32_t dw_offset,
			    uint64_t vaddr, uint32_t data)
{
	/* Check that softpin addresses are in the correct form */
	igt_assert_eq_u64(vaddr, igt_canonical_address(vaddr));

	/* SDI cannot write to unaligned addresses */
	igt_assert((vaddr & 3) == 0);

	cmd_buf[dw_offset++] = MI_STORE_DWORD_IMM;
	cmd_buf[dw_offset++] = (uint32_t)vaddr;
	cmd_buf[dw_offset++] = (uint32_t)(vaddr >> 32);
	cmd_buf[dw_offset++] = data;

	return dw_offset;
}

/* emit_store_qword
 * populate batch buffer with MI_STORE_DWORD_IMM command
 * @fd: drm file descriptor
 * @cmd_buf: batch buffer
 * @dw_offset: write offset in batch buffer
 * @vaddr: destination Virtual address
 * @data: u64 data to be stored at destination
 */
static int emit_store_qword(int fd, uint32_t *cmd_buf, uint32_t dw_offset,
			    uint64_t vaddr, uint64_t data)
{
	/* Check that softpin addresses are in the correct form */
	igt_assert_eq_u64(vaddr, igt_canonical_address(vaddr));

	/* SDI cannot write to unaligned addresses */
	igt_assert((vaddr & 7) == 0);

	cmd_buf[dw_offset++] = MI_STORE_DWORD_IMM | 0x3;
	cmd_buf[dw_offset++] = (uint32_t)vaddr;
	cmd_buf[dw_offset++] = (uint32_t)(vaddr >> 32);
	cmd_buf[dw_offset++] = data;
	cmd_buf[dw_offset++] = data >> 32;

	return dw_offset;
}

/* emit_bb_end
 * populate batch buffer with MI_BATCH_BUFFER_END command
 * @fd: drm file descriptor
 * @cmd_buf: batch buffer
 * @dw_offset: write offset in batch buffer
 */
static int emit_bb_end(int fd, uint32_t *cmd_buf, uint32_t dw_offset)
{
	dw_offset = ALIGN(dw_offset, 2);
	cmd_buf[dw_offset++] = MI_BATCH_BUFFER_END;
	dw_offset++;

	return dw_offset;
}

/* setup_execbuffer
 * helper for buffer execution
 * @execbuf - pointer to execbuffer
 * @exec_object - pointer to exec object2 struct
 * @ring - ring to be used
 * @buffer_count - how manu buffers to submit
 * @batch_length - length of batch buffer
 */
static void setup_execbuffer(struct drm_i915_gem_execbuffer2 *execbuf,
			     struct drm_i915_gem_exec_object2 *exec_object,
			     uint32_t ctx_id, int ring, int buffer_count, int batch_length)
{
	memset(execbuf, 0, sizeof(*execbuf));

	execbuf->buffers_ptr = (unsigned long)exec_object;
	execbuf->buffer_count = buffer_count;
	execbuf->batch_len = batch_length;
	execbuf->flags = ring;
	i915_execbuffer2_set_context_id(*execbuf, ctx_id);
}

#define TABLE_SIZE 0x1000
#define TILE_SIZE 0x10000

#define TRTT_SEGMENT_SIZE (1ULL << 44)
#define PPGTT_SIZE (1ULL << 48)

#define NULL_TILE_PATTERN    0xFFFFFFFF
#define INVALID_TILE_PATTERN 0xFFFFFFFE

struct local_i915_gem_context_trtt_param {
	uint64_t segment_base_addr;
	uint64_t l3_table_address;
	uint32_t invd_tile_val;
	uint32_t null_tile_val;
};

/* query_trtt
 * Helper function to check if the TR-TT settings stored with the KMD,
 * for a context, have the expected values (set previously).
 * @fd - drm fd
 * @ctx_id - id of the context for which TRTT is to be enabled
 * @l3_table_address - GFX address of the L3 table
 * @segment_base_addr - offset of the TRTT segment in PPGTT space
 */
static void
query_trtt(int fd, uint32_t ctx_id, uint64_t l3_table_address,
	   uint64_t segment_base_addr)
{
	struct local_i915_gem_context_param ctx_param;
	struct local_i915_gem_context_trtt_param trtt_param;

	ctx_param.context = ctx_id;
	ctx_param.size = sizeof(trtt_param);
	ctx_param.param = LOCAL_CONTEXT_PARAM_TRTT;
	ctx_param.value = (uint64_t)&trtt_param;

	gem_context_get_param(fd, &ctx_param);

	igt_assert_eq_u64(trtt_param.l3_table_address, l3_table_address);
	igt_assert_eq_u64(trtt_param.segment_base_addr, segment_base_addr);
	igt_assert_eq_u32(trtt_param.invd_tile_val, INVALID_TILE_PATTERN);
	igt_assert_eq_u32(trtt_param.null_tile_val, NULL_TILE_PATTERN);
}

static int
__setup_trtt(int fd, uint32_t ctx_id, uint64_t l3_table_address,
	     uint64_t segment_base_addr, uint32_t null_tile_val,
	     uint32_t invd_tile_val)
{
	struct local_i915_gem_context_param ctx_param;
	struct local_i915_gem_context_trtt_param trtt_param;

	trtt_param.null_tile_val = null_tile_val;
	trtt_param.invd_tile_val = invd_tile_val;
	trtt_param.l3_table_address = l3_table_address;
	trtt_param.segment_base_addr = segment_base_addr;

	ctx_param.context = ctx_id;
	ctx_param.size = sizeof(trtt_param);
	ctx_param.param = LOCAL_CONTEXT_PARAM_TRTT;
	ctx_param.value = (uint64_t)&trtt_param;

	return __gem_context_set_param(fd, &ctx_param);
}

/* setup_trtt
 * Helper function to request KMD to enable TRTT
 * @fd - drm fd
 * @ctx_id - id of the context for which TRTT is to be enabled
 * @l3_table_address - GFX address of the L3 table
 * @segment_base_addr - offset of the TRTT segment in PPGTT space
 */
static int
setup_trtt(int fd, uint32_t ctx_id, uint64_t l3_table_address,
	   uint64_t segment_base_addr)
{
	return __setup_trtt(fd, ctx_id, l3_table_address, segment_base_addr,
			NULL_TILE_PATTERN, INVALID_TILE_PATTERN);
}

/* bo_alloc_setup
 * allocate bo and populate exec object
 * @exec_object2 - pointer to exec object
 * @bo_sizee - buffer size
 * @flags - exec flags
 * @bo_offset - pointer to the current PPGTT offset
 */
static void bo_alloc_setup(int fd, struct drm_i915_gem_exec_object2 *exec_object2,
			   uint64_t bo_size, uint64_t flags, uint64_t *bo_offset)
{
	memset(exec_object2, 0, sizeof(*exec_object2));
	exec_object2->handle = gem_create(fd, bo_size);
	exec_object2->flags = flags;

	if (bo_offset)
	{
		exec_object2->offset = *bo_offset;
		*bo_offset += bo_size;
	}
}

/* busy_batch
 * This helper function will prepare & submit a batch on the BCS ring,
 * which will keep the ring busy for sometime, long enough to submit
 * some other work which can trigger the eviction of that batch object
 * while it is still getting executed on the ring.
 */
static uint64_t busy_batch(int fd, uint32_t ctx_id)
{
	const int gen = intel_gen(intel_get_drm_devid(fd));
	const int has_64bit_reloc = gen >= 8;
	struct drm_i915_gem_execbuffer2 execbuf;
	struct drm_i915_gem_exec_object2 object[2];
	uint32_t *map;
	int factor = 10;
	int i = 0;

	/* Until the kernel ABI is fixed, only default contexts can be used
	 * on !RCS rings */
	igt_require(ctx_id == 0);

	memset(object, 0, sizeof(object));
	object[0].handle = gem_create(fd, 1024*1024);
	object[1].handle = gem_create(fd, 4096);
	map = gem_mmap__cpu(fd, object[1].handle, 0, 4096, PROT_WRITE);
	gem_set_domain(fd, object[1].handle,
		       I915_GEM_DOMAIN_CPU, I915_GEM_DOMAIN_CPU);

	setup_execbuffer(&execbuf, object, ctx_id, I915_EXEC_BLT, 2,
			 emit_bb_end(fd, map, 0)*4);
	gem_execbuf(fd, &execbuf);

	igt_debug("Active offsets = [%08llx, %08llx]\n",
		  object[0].offset, object[1].offset);

#define COPY_BLT_CMD		(2<<29|0x53<<22|0x6)
#define BLT_WRITE_ALPHA		(1<<21)
#define BLT_WRITE_RGB		(1<<20)
	gem_set_domain(fd, object[1].handle,
		       I915_GEM_DOMAIN_CPU, I915_GEM_DOMAIN_CPU);
	while (factor--) {
		/* XY_SRC_COPY */
		map[i++] = COPY_BLT_CMD | BLT_WRITE_ALPHA | BLT_WRITE_RGB;
		if (has_64bit_reloc)
			map[i-1] += 2;
		map[i++] = 0xcc << 16 | 1 << 25 | 1 << 24 | (4*1024);
		map[i++] = 0;
		map[i++] = 256 << 16 | 1024;
		map[i++] = object[0].offset;
		if (has_64bit_reloc)
			map[i++] = object[0].offset >> 32;
		map[i++] = 0;
		map[i++] = 4096;
		map[i++] = object[0].offset;
		if (has_64bit_reloc)
			map[i++] = object[0].offset >> 32;
	}
	i = emit_bb_end(fd, map, i);
	munmap(map, 4096);

	object[0].flags = EXEC_OBJECT_PINNED | EXEC_OBJECT_WRITE;
	object[1].flags = EXEC_OBJECT_PINNED;
	execbuf.batch_len = i*4;
	gem_execbuf(fd, &execbuf);
	gem_close(fd, object[0].handle);
	gem_close(fd, object[1].handle);

	return object[1].offset;
}

/* active object eviction test
 * This test will force the eviction of an active object, by choosing the
 * TR-TT segment location which will overlap with the object's location.
 */
static void test_evict_active(void)
{
	int fd;
	uint64_t expected;
	uint64_t segment_base_addr;
	uint64_t l3_offset;

	fd = drm_open_driver(DRIVER_INTEL);

	expected = busy_batch(fd, 0);

	/* Determine the segment_base_addr according to the offset of active
	 * buffer, forcing its eviction
	 */
	segment_base_addr = expected & (~(TRTT_SEGMENT_SIZE - 1));

	/* Keep the l3 table outside the segment to avoid the conflict */
	l3_offset = segment_base_addr ? 0 : TRTT_SEGMENT_SIZE;

	igt_assert(setup_trtt(fd, 0, l3_offset, segment_base_addr) == 0);

	query_trtt(fd, 0, l3_offset, segment_base_addr);
	close(fd);
}

/* hanging object eviction test
 * This test will force the eviction of a hanging object, by choosing the
 * TR-TT segment location which will overlap with the object's location.
 */
static void test_evict_hang(void)
{
	int fd;
	uint32_t ctx_id;
	uint64_t segment_base_addr;
	uint64_t l3_offset;
	uint64_t expected;

	fd = drm_open_driver(DRIVER_INTEL);
	ctx_id = gem_context_create(fd);

	igt_hang_ctx(fd, ctx_id, I915_EXEC_RENDER, 0, (uint64_t *)&expected);

	/* Determine the segment_base_addr according to the offset of hanging
	 * buffer, forcing its eviction
	 */
	segment_base_addr = expected & (~(TRTT_SEGMENT_SIZE - 1));

	/* Keep the l3 table outside the segment to avoid the conflict */
	l3_offset = segment_base_addr ? 0 : TRTT_SEGMENT_SIZE;

	igt_assert(setup_trtt(fd, ctx_id, l3_offset, segment_base_addr) == 0);

	query_trtt(fd, ctx_id, l3_offset, segment_base_addr);
	gem_context_destroy(fd, ctx_id);
	close (fd);
}

/* submit_trtt_context
 * This helper function will create a new context if the TR-TT segment
 * base address is not zero, allocate a L3 table page, 2 pages apiece
 * for L2/L1 tables and couple of data buffers of 64KB in size, matching the
 * Tile size. The 2 data buffers will be mapped to the 2 ends of TRTT virtual
 * space. Series of MI_STORE_DWORD_IMM commands will be added in the batch
 * buffer to first update the TR-TT table entries and then to update the data
 * buffers using their TR-TT VA, exercising the table programming done
 * previously.
 * Invoke CONTEXT_SETPARAM ioctl to request KMD to enable TRTT.
 * Invoke execbuffer to submit the batch buffer.
 * Verify value of first DWORD in the 2 data buffer matches the data asked
 * to be written by the GPU.
 */
static void submit_trtt_context(int fd, uint64_t segment_base_addr, uint32_t ctx_id)
{
	enum {
		L3_TBL,
		L2_TBL1,
		L2_TBL2,
		L1_TBL1,
		L1_TBL2,
		DATA1,
		DATA2,
		BATCH,
		NUM_BUFFERS,
	};

	int ring, len = 0;
	uint32_t *ptr;
	struct drm_i915_gem_execbuffer2 execbuf;
	struct drm_i915_gem_exec_object2 exec_object2[NUM_BUFFERS];
	uint32_t batch_buffer[BO_SIZE];
	uint32_t data, last_entry_offset;
	uint64_t cur_ppgtt_off, exec_flags;
	uint64_t first_tile_addr, last_tile_addr;

	first_tile_addr = segment_base_addr;
	last_tile_addr  = first_tile_addr + TRTT_SEGMENT_SIZE - TILE_SIZE;

	/* To avoid conflict with the TR-TT segment */
	cur_ppgtt_off = segment_base_addr ? 0 : TRTT_SEGMENT_SIZE;

	exec_flags = EXEC_OBJECT_SUPPORTS_48B_ADDRESS;

	/* first allocate Batch buffer BO */
	bo_alloc_setup(fd, &exec_object2[BATCH], BO_SIZE, exec_flags, NULL);

	/* table BOs and data buffer BOs are written by GPU and are soft pinned */
	exec_flags |= (EXEC_OBJECT_WRITE | EXEC_OBJECT_PINNED);

	/* Allocate a L3 table BO */
	bo_alloc_setup(fd, &exec_object2[L3_TBL], TABLE_SIZE, exec_flags, &cur_ppgtt_off);

	/* Allocate two L2 table BOs */
	bo_alloc_setup(fd, &exec_object2[L2_TBL1], TABLE_SIZE, exec_flags, &cur_ppgtt_off);
	bo_alloc_setup(fd, &exec_object2[L2_TBL2], TABLE_SIZE, exec_flags, &cur_ppgtt_off);

	/* Allocate two L1 table BOs */
	bo_alloc_setup(fd, &exec_object2[L1_TBL1], TABLE_SIZE, exec_flags, &cur_ppgtt_off);
	bo_alloc_setup(fd, &exec_object2[L1_TBL2], TABLE_SIZE, exec_flags, &cur_ppgtt_off);

	/* Align the PPGTT offsets for the 2 data buffers to next 64 KB boundary */
	cur_ppgtt_off = ALIGN(cur_ppgtt_off, TILE_SIZE);

	/* Allocate two Data buffer BOs */
	bo_alloc_setup(fd, &exec_object2[DATA1], TILE_SIZE, exec_flags, &cur_ppgtt_off);
	bo_alloc_setup(fd, &exec_object2[DATA2], TILE_SIZE, exec_flags, &cur_ppgtt_off);

	/* Add commands to update the two L3 table entries to point them to the L2 tables*/
	last_entry_offset = 511*sizeof(uint64_t);

	len = emit_store_qword(fd, batch_buffer, len,
			       exec_object2[L3_TBL].offset,
			       exec_object2[L2_TBL1].offset);

	len = emit_store_qword(fd, batch_buffer, len,
			       exec_object2[L3_TBL].offset + last_entry_offset,
			       exec_object2[L2_TBL2].offset);

	/* Add commands to update an entry of 2 L2 tables to point them to the L1 tables*/
	len = emit_store_qword(fd, batch_buffer, len,
			       exec_object2[L2_TBL1].offset,
			       exec_object2[L1_TBL1].offset);

	len = emit_store_qword(fd, batch_buffer, len,
			       exec_object2[L2_TBL2].offset + last_entry_offset,
			       exec_object2[L1_TBL2].offset);

	/* Add commands to update an entry of 2 L1 tables to point them to the data buffers*/
	last_entry_offset = 1023*sizeof(uint32_t);

	len = emit_store_dword(fd, batch_buffer, len,
			       exec_object2[L1_TBL1].offset,
			       exec_object2[DATA1].offset >> 16);

	len = emit_store_dword(fd, batch_buffer, len,
			       exec_object2[L1_TBL2].offset + last_entry_offset,
			       exec_object2[DATA2].offset >> 16);

	/* Add commands to update the 2 data buffers, using their TRTT VA */
	data = 0x12345678;
	len = emit_store_dword(fd, batch_buffer, len,
			       igt_canonical_address(first_tile_addr),
			       data);
	len = emit_store_dword(fd, batch_buffer, len,
			       igt_canonical_address(last_tile_addr),
			       data);

	len = emit_bb_end(fd, batch_buffer, len);
	gem_write(fd, exec_object2[BATCH].handle, 0, batch_buffer, len*4);

	/* Request KMD to setup the TR-TT */
	igt_assert(setup_trtt(fd, ctx_id, exec_object2[L3_TBL].offset, first_tile_addr) == 0);

	ring = I915_EXEC_RENDER;
	setup_execbuffer(&execbuf, exec_object2, ctx_id, ring, NUM_BUFFERS, len*4);

	/* submit command buffer */
	gem_execbuf(fd, &execbuf);

	/* read the 2 data buffers to check for the value written by the GPU */
	ptr = mmap_bo(fd, exec_object2[DATA1].handle, TILE_SIZE);
	igt_assert_eq_u32(ptr[0], data);

	ptr = mmap_bo(fd, exec_object2[DATA2].handle, TILE_SIZE);
	igt_assert_eq_u32(ptr[0], data);

	gem_close(fd, exec_object2[L3_TBL].handle);
	gem_close(fd, exec_object2[L2_TBL1].handle);
	gem_close(fd, exec_object2[L2_TBL2].handle);
	gem_close(fd, exec_object2[L1_TBL1].handle);
	gem_close(fd, exec_object2[L1_TBL2].handle);
	gem_close(fd, exec_object2[DATA1].handle);
	gem_close(fd, exec_object2[DATA2].handle);
	gem_close(fd, exec_object2[BATCH].handle);

	/* Check if the TRTT params stored with the Driver are intact or not */
	query_trtt(fd, ctx_id, exec_object2[L3_TBL].offset, first_tile_addr);
}

/* basic trtt test
 * This will test the basic TR-TT functionality by doing couple of store
 * operations through it. Also it will exercise all possible TR-TT segment
 * start locations (i.e. 16 of them) for both default & User created contexts.
 */
static void test_basic_trtt_use(void)
{
	int fd;
	uint32_t ctx_id;
	uint64_t segment_base_addr;

	for (segment_base_addr = 0;
	     segment_base_addr < PPGTT_SIZE;
	     segment_base_addr += TRTT_SEGMENT_SIZE)
	{
		/* In order to test the default context for all segment start
		 * locations, need to open a new file instance on every iteration
		 * as TRTT settings are immutable once set for a context.
		 */
		fd = drm_open_driver(DRIVER_INTEL);

		submit_trtt_context(fd, segment_base_addr, 0);

		ctx_id = gem_context_create(fd);
		submit_trtt_context(fd, segment_base_addr, ctx_id);
		gem_context_destroy(fd, ctx_id);

		close(fd);
	}
}

static void test_invalid(void)
{
	int fd;
	uint32_t ctx_id;
	uint64_t segment_base_addr;
	uint64_t l3_offset;

	fd = drm_open_driver(DRIVER_INTEL);
	ctx_id = gem_context_create(fd);

	/* Check for an incorrectly aligned base location for TR-TT segment */
	segment_base_addr = TRTT_SEGMENT_SIZE + 0x1000;
	l3_offset = TILE_SIZE;
	igt_assert_eq(setup_trtt(fd, ctx_id, l3_offset, segment_base_addr), -EINVAL);

	/* Correct the segment_base_addr value */
	segment_base_addr = TRTT_SEGMENT_SIZE;

	/* Check for the same/conflicting value for L3 table and TR-TT segment location */
	l3_offset = segment_base_addr;
	igt_assert_eq(setup_trtt(fd, ctx_id, l3_offset, segment_base_addr), -EINVAL);

	/* Check for an incorrectly aligned location for L3 table */
	l3_offset = TILE_SIZE + 0x1000;
	igt_assert_eq(setup_trtt(fd, ctx_id, l3_offset, segment_base_addr), -EINVAL);

	/* Correct the l3_offset value */
	l3_offset = TILE_SIZE;

	/* Check for the same value for Null & Invalid tile patterns */
	igt_assert_eq(__setup_trtt(fd, ctx_id, l3_offset, segment_base_addr,
				   NULL_TILE_PATTERN, NULL_TILE_PATTERN), -EINVAL);

	/* Use the correct settings now */
	igt_assert(setup_trtt(fd, ctx_id, l3_offset, segment_base_addr) == 0);
	/* Check the overriding of TR-TT settings for the same context */
	segment_base_addr += TRTT_SEGMENT_SIZE;
	l3_offset += TILE_SIZE;
	igt_assert_eq(setup_trtt(fd, ctx_id, l3_offset, segment_base_addr), -EEXIST);

	gem_context_destroy(fd, ctx_id);
	close(fd);
}

igt_main
{
	int fd = -1;

	igt_fixture {
		fd = drm_open_driver(DRIVER_INTEL);

		igt_require(has_trtt_support(fd));
		/* test also needs 48 PPGTT & Soft Pin support */
		igt_require(gem_has_softpin(fd));
		igt_require(gem_uses_64b_ppgtt(fd));
	}

	/* Each subtest will open its own private file instance to avoid
	 * any interference. Otherwise once TRTT is enabled for the default
	 * context with segment_base_addr value of 0, all the other tests which
	 * are implicitly done, such as quiescent_gpu, will break as they only
	 * use the default context and do not use the 48B_ADDRESS flag for it.
	 */

	igt_subtest("invalid")
		test_invalid();

	igt_subtest("basic")
		test_basic_trtt_use();

	igt_subtest("evict_active")
		test_evict_active();

	igt_subtest("evict_hang")
		test_evict_hang();

	igt_subtest("evict_active-interruptible")
		igt_while_interruptible(true) test_evict_active();

	igt_fixture
		close(fd);
}
