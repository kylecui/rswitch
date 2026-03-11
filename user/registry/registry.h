// SPDX-License-Identifier: GPL-2.0
#ifndef RSWITCH_REGISTRY_H
#define RSWITCH_REGISTRY_H

#define REGISTRY_DEFAULT_URL "https://registry.rswitch.dev"
#define REGISTRY_LOCAL_CACHE "~/.rswitch/modules"
#define REGISTRY_INDEX_FILE "/var/lib/rswitch/registry/index.json"
#define REGISTRY_MAX_RESULTS 50

struct rs_registry_entry {
    char name[64];
    char version[32];
    char abi_version[16];
    char author[128];
    char description[256];
    unsigned int stage;
    char hook[16];
    unsigned int flags;
    char license[32];
    char checksum[72]; /* sha256:hex */
};

/* Search local registry index for modules matching query */
int rs_registry_search(const char *query, struct rs_registry_entry *results, int max_results);

/* Get info about a specific module from registry */
int rs_registry_info(const char *name, struct rs_registry_entry *entry);

/* Install a module from registry (download + verify + install) */
int rs_registry_install(const char *name, const char *version);

/* Publish a .rsmod package to registry */
int rs_registry_publish(const char *rsmod_path);

/* Initialize/update registry index from local .rsmod files */
int rs_registry_update_index(void);

#endif
