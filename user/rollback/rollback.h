// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_ROLLBACK_H
#define RSWITCH_ROLLBACK_H

#include <stdint.h>

#define ROLLBACK_SNAPSHOT_DIR "/var/lib/rswitch/snapshots"
#define ROLLBACK_MAX_SNAPSHOTS 10
#define ROLLBACK_DEFAULT_CONFIRM_TIMEOUT 300  /* seconds */

struct rs_snapshot_info {
	char id[32];           /* timestamp-based ID: YYYYMMDD-HHMMSS */
	char description[128];
	char profile_path[256];
	uint64_t timestamp;
	int confirmed;
};

/* Create a snapshot of current running config */
int rs_rollback_create_snapshot(const char *description);

/* List all snapshots */
int rs_rollback_list_snapshots(struct rs_snapshot_info *snapshots, int max);

/* Apply a profile with confirm timeout -- auto-rollback if not confirmed */
int rs_rollback_apply(const char *profile_path, int confirm_timeout_sec);

/* Confirm the pending apply (cancel auto-rollback timer) */
int rs_rollback_confirm(void);

/* Rollback to a specific snapshot (or latest if id is NULL) */
int rs_rollback_to(const char *snapshot_id);

/* Get pending apply status */
int rs_rollback_pending_status(char *snapshot_id, int *remaining_sec);

#endif
