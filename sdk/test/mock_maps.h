/* rSwitch Map Mocking for Offline Tests
 *
 * Provides mock implementations of BPF map operations
 * for testing module logic without loading into the kernel.
 */
#ifndef __RS_MOCK_MAPS_H
#define __RS_MOCK_MAPS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple in-memory hash map mock */
#define RS_MOCK_MAP_SIZE 1024

struct rs_mock_entry {
    void *key;
    void *value;
    int key_size;
    int value_size;
    int in_use;
};

struct rs_mock_map {
    struct rs_mock_entry entries[RS_MOCK_MAP_SIZE];
    int key_size;
    int value_size;
    int count;
};

static struct rs_mock_map *rs_mock_map_create(int key_size, int value_size)
{
    struct rs_mock_map *map = (struct rs_mock_map *)calloc(1, sizeof(*map));
    if (map) {
        map->key_size = key_size;
        map->value_size = value_size;
    }
    return map;
}

static void rs_mock_map_destroy(struct rs_mock_map *map)
{
    if (!map)
        return;
    for (int i = 0; i < RS_MOCK_MAP_SIZE; i++) {
        if (map->entries[i].in_use) {
            free(map->entries[i].key);
            free(map->entries[i].value);
        }
    }
    free(map);
}

static int rs_mock_map_update(struct rs_mock_map *map, const void *key, const void *value)
{
    /* Find existing or empty slot */
    int empty = -1;
    for (int i = 0; i < RS_MOCK_MAP_SIZE; i++) {
        if (map->entries[i].in_use &&
            memcmp(map->entries[i].key, key, map->key_size) == 0) {
            memcpy(map->entries[i].value, value, map->value_size);
            return 0;
        }
        if (!map->entries[i].in_use && empty < 0)
            empty = i;
    }
    if (empty < 0)
        return -1;

    map->entries[empty].key = malloc(map->key_size);
    map->entries[empty].value = malloc(map->value_size);
    memcpy(map->entries[empty].key, key, map->key_size);
    memcpy(map->entries[empty].value, value, map->value_size);
    map->entries[empty].key_size = map->key_size;
    map->entries[empty].value_size = map->value_size;
    map->entries[empty].in_use = 1;
    map->count++;
    return 0;
}

static void *rs_mock_map_lookup(struct rs_mock_map *map, const void *key)
{
    for (int i = 0; i < RS_MOCK_MAP_SIZE; i++) {
        if (map->entries[i].in_use &&
            memcmp(map->entries[i].key, key, map->key_size) == 0) {
            return map->entries[i].value;
        }
    }
    return NULL;
}

#endif /* __RS_MOCK_MAPS_H */
