#ifndef RS_FUZZ_H
#define RS_FUZZ_H

#include <linux/types.h>
#include <stddef.h>

struct rs_fuzz_ctx;

struct rs_fuzz_ctx *rs_fuzz_init(const char *obj_path, const char *prog_name);
int rs_fuzz_run(struct rs_fuzz_ctx *ctx, const void *data, size_t size, __u32 *retval);
void rs_fuzz_close(struct rs_fuzz_ctx *ctx);

#endif
