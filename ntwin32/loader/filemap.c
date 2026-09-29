/* SPDX-License-Identifier: GPL-2.0-only */
#include "filemap.h"
#include "winfile.h"
#define NTW_MAP_PRIVATE 2
#define NTW_MAP_ANON 0x20
#define NTW_MAP_SLOTS 32u
#define NTW_MAP_VIEWS 64u
#define NTW_MAP_NAME 64u
typedef struct ntw_section {
    uint32_t live, protect, size, reserved, refs;
    uint16_t name[NTW_MAP_NAME];
    uint8_t *base;
    uint32_t bytes;
} ntw_section;
typedef struct ntw_view {
    uint32_t live, section, bytes;
    uintptr_t address;
} ntw_view;
typedef struct ntw_map_handle { uint32_t live, section; } ntw_map_handle;
static ntw_section sections[NTW_MAP_SLOTS];
static ntw_map_handle handles[NTW_MAP_SLOTS];
static ntw_view views[NTW_MAP_VIEWS];
static ntw_map_place map_place;
static ntw_map_remove map_remove;
static ntw_map_protect map_change;
static void *map_user;
void ntw_filemap_set_ops(ntw_map_place place, ntw_map_remove remove, ntw_map_protect protect, void *user) {
    map_place = place;
    map_remove = remove;
    map_change = protect;
    map_user = user;
}
void ntw_filemap_reset(void) {
    uint32_t i;
    for (i = 0; i < NTW_MAP_SLOTS; ++i) { sections[i].live = 0; handles[i].live = 0; }
    for (i = 0; i < NTW_MAP_VIEWS; ++i) views[i].live = 0;
}
static int alloc_handle(uint32_t section, uint32_t *out) {
    uint32_t i;
    for (i = 0; i < NTW_MAP_SLOTS; ++i) if (!handles[i].live) {
        handles[i].live = 1;
        handles[i].section = section;
        *out = 0x3000u + i;
        return 1;
    }
    return 0;
}
static int lookup_handle(uint32_t mapping, ntw_section **section, uint32_t *index) {
    uint32_t slot;
    if (mapping < 0x3000u || mapping >= 0x3000u + NTW_MAP_SLOTS) return 0;
    slot = mapping - 0x3000u;
    if (!handles[slot].live || !sections[handles[slot].section].live) return 0;
    if (section) *section = &sections[handles[slot].section];
    if (index) *index = slot;
    return 1;
}
static int page_bits(uint32_t protect, int *prot, int *write, int *copy, int *execute) {
    switch (protect & 0xffu) {
    case NTW_MAP_PAGE_READONLY: *prot = 1; *write = 0; *copy = 1; *execute = 0; break;
    case NTW_MAP_PAGE_READWRITE: *prot = 3; *write = 1; *copy = 1; *execute = 0; break;
    case NTW_MAP_PAGE_WRITECOPY: *prot = 3; *write = 0; *copy = 1; *execute = 0; break;
    case NTW_MAP_PAGE_EXECUTE_READ: *prot = 5; *write = 0; *copy = 1; *execute = 1; break;
    case NTW_MAP_PAGE_EXECUTE_READWRITE: *prot = 7; *write = 1; *copy = 1; *execute = 1; break;
    case NTW_MAP_PAGE_EXECUTE_WRITECOPY: *prot = 7; *write = 0; *copy = 1; *execute = 1; break;
    default: return 0;
    }
    return 1;
}
static int same_name(const uint16_t *left, const uint16_t *right) {
    uint32_t i = 0;
    if (!left || !right || !left[0]) return 0;
    for (; left[i] && right[i]; ++i) {
        uint16_t a = left[i], b = right[i];
        if (a >= 'A' && a <= 'Z') a = (uint16_t)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (uint16_t)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return left[i] == right[i];
}
static int access_ok(uint32_t protect, uint32_t access, int *prot) {
    int write = 0, copy = 0, execute = 0;
    uint32_t mode = access & (NTW_MAP_READ | NTW_MAP_WRITE | NTW_MAP_COPY | NTW_MAP_EXECUTE);
    if (!page_bits(protect, prot, &write, &copy, &execute)) return 0;
    if (!mode) return 0;
    if ((mode & NTW_MAP_WRITE) && !write) return 0;
    if ((mode & NTW_MAP_COPY) && !copy) return 0;
    if ((mode & NTW_MAP_EXECUTE) && !execute) return 0;
    *prot = (mode & NTW_MAP_EXECUTE) ? (*prot | 4) : (*prot & ~4);
    if (!(mode & (NTW_MAP_WRITE | NTW_MAP_COPY))) *prot = (*prot & 4) | 1;
    else *prot = (*prot & 4) | 3;
    return 1;
}
static void destroy_section(ntw_section *section) {
    uint32_t i;
    for (i = 0; i < NTW_MAP_VIEWS; ++i) if (views[i].live && views[i].section == (uint32_t)(section - sections))
        views[i].live = 0;
    if (section->base && map_remove) map_remove(map_user, section->base, section->bytes);
    section->live = 0;
    section->base = 0;
}
uint32_t ntw_filemap_create(uint32_t file, uint32_t protect, uint32_t size_high, uint32_t size_low,
                            const uint16_t *name, uint32_t *error) {
    uint32_t extra = protect & ~0xffu, i, slot = NTW_MAP_SLOTS, bytes;
    int prot = 0, write = 0, copy = 0, execute = 0;
    void *memory;
    if (error) *error = 0;
    if (size_high || (extra & ~(NTW_MAP_SEC_COMMIT | NTW_MAP_SEC_RESERVE | NTW_MAP_SEC_NOCACHE)) ||
        ((extra & NTW_MAP_SEC_COMMIT) && (extra & NTW_MAP_SEC_RESERVE)) ||
        !page_bits(protect, &prot, &write, &copy, &execute)) {
        if (error) *error = NTW_ERR_INVALID;
        return 0;
    }
    (void)write; (void)copy; (void)execute;
    if (file != NTW_MAP_INVALID_FILE) {
        uint32_t lo = 0, hi = 0, err = 0;
        if (!ntw_winfile_owns(file) || !ntw_winfile_size(file, &lo, &hi, &err) || hi) {
            if (error) *error = NTW_ERR_HANDLE;
            return 0;
        }
        if (!size_low) size_low = lo;
        if (!size_low) { if (error) *error = NTW_ERR_INVALID; return 0; }
    } else if (!size_low) { if (error) *error = NTW_ERR_INVALID; return 0; }
    if (name && name[0]) {
        for (i = 0; i < NTW_MAP_SLOTS; ++i) if (sections[i].live && same_name(sections[i].name, name)) {
            uint32_t existing = 0, h;
            if ((sections[i].protect & 0xffu) != (protect & 0xffu)) { if (error) *error = NTW_ERR_ACCESS; return 0; }
            for (h = 0; h < NTW_MAP_SLOTS; ++h) if (handles[h].live && handles[h].section == i) { existing = 0x3000u + h; break; }
            if (!existing) { if (error) *error = NTW_ERR_HANDLE; return 0; }
            if (error) *error = NTW_ERR_EXISTS;
            return existing;
        }
    }
    for (i = 0; i < NTW_MAP_SLOTS; ++i) if (!sections[i].live) { slot = i; break; }
    if (slot == NTW_MAP_SLOTS || !map_place) { if (error) *error = NTW_ERR_NOMEM; return 0; }
    bytes = (size_low + 4095u) & ~4095u;
    memory = map_place(map_user, 0, bytes,
                       (extra & NTW_MAP_SEC_RESERVE) ? 0 : (file != NTW_MAP_INVALID_FILE ? 3 : prot),
                       NTW_MAP_PRIVATE | NTW_MAP_ANON);
    if (!memory) { if (error) *error = NTW_ERR_NOMEM; return 0; }
    sections[slot].live = 1;
    sections[slot].protect = protect;
    sections[slot].size = size_low;
    sections[slot].reserved = (extra & NTW_MAP_SEC_RESERVE) ? 1u : 0u;
    sections[slot].refs = 1;
    sections[slot].base = memory;
    sections[slot].bytes = bytes;
    if (file != NTW_MAP_INVALID_FILE) {
        uint32_t err = 0, pos_lo = 0, pos_hi = 0, done = 0, got = 0;
        if (!ntw_winfile_seek(file, 0, 0, &pos_lo, &pos_hi, 1, &err) ||
            !ntw_winfile_seek(file, 0, 0, 0, 0, 0, &err)) {
            destroy_section(&sections[slot]);
            if (error) *error = NTW_ERR_HANDLE;
            return 0;
        }
        while (done < size_low) {
            uint32_t chunk = size_low - done;
            if (chunk > 65536u) chunk = 65536u;
            if (!ntw_winfile_read(file, (uint8_t *)memory + done, chunk, &got, 0, &err) || !got) break;
            done += got;
        }
        ntw_winfile_seek(file, pos_lo, pos_hi, 0, 0, 0, &err);
        if (!done) {
            destroy_section(&sections[slot]);
            if (error) *error = NTW_ERR_ACCESS;
            return 0;
        }
        if (done < size_low) {
            uint32_t n;
            for (n = done; n < size_low; ++n) ((uint8_t *)memory)[n] = 0;
        }
        if (!(extra & NTW_MAP_SEC_RESERVE) && map_change &&
            map_change(map_user, memory, bytes, prot) != 0) {
            destroy_section(&sections[slot]);
            if (error) *error = NTW_ERR_NOMEM;
            return 0;
        }
    }
    for (i = 0; i < NTW_MAP_NAME; ++i) sections[slot].name[i] = 0;
    if (name) for (i = 0; name[i] && i + 1 < NTW_MAP_NAME; ++i) sections[slot].name[i] = name[i];
    if (!alloc_handle(slot, &i)) { destroy_section(&sections[slot]); if (error) *error = NTW_ERR_NOMEM; return 0; }
    return i;
}
uintptr_t ntw_filemap_view(uint32_t mapping, uint32_t access, uint32_t offset_high, uint32_t offset_low,
                          uint32_t bytes, uint32_t *error) {
    uint32_t index, i, length, view = NTW_MAP_VIEWS;
    int prot = 0;
    ntw_section *section;
    if (error) *error = 0;
    if (!lookup_handle(mapping, &section, 0) || offset_high) {
        if (error) *error = lookup_handle(mapping, 0, 0) ? NTW_ERR_INVALID : NTW_ERR_HANDLE;
        return 0;
    }
    index = handles[mapping - 0x3000u].section;
    if ((offset_low & 65535u) || !access_ok(section->protect, access, &prot)) {
        if (error) *error = (offset_low & 65535u) ? NTW_ERR_INVALID : NTW_ERR_ACCESS;
        return 0;
    }
    if (offset_low >= section->size) { if (error) *error = NTW_ERR_INVALID; return 0; }
    length = bytes ? bytes : section->size - offset_low;
    if (length > section->size - offset_low) { if (error) *error = NTW_ERR_INVALID; return 0; }
    for (i = 0; i < NTW_MAP_VIEWS; ++i) if (!views[i].live) { view = i; break; }
    if (view == NTW_MAP_VIEWS || !map_change) { if (error) *error = NTW_ERR_NOMEM; return 0; }
    if (map_change(map_user, section->base + offset_low, (length + 4095u) & ~4095u, prot) != 0) {
        if (error) *error = NTW_ERR_NOMEM;
        return 0;
    }
    views[view].live = 1;
    views[view].section = index;
    views[view].address = (uintptr_t)(section->base + offset_low);
    views[view].bytes = length;
    section->refs++;
    return views[view].address;
}
int ntw_filemap_unmap(uintptr_t address, uint32_t *error) {
    uint32_t i;
    if (!address) { if (error) *error = NTW_ERR_INVALID; return 0; }
    for (i = 0; i < NTW_MAP_VIEWS; ++i) if (views[i].live && views[i].address == address) {
        ntw_section *section = &sections[views[i].section];
        uint32_t length = (views[i].bytes + 4095u) & ~4095u;
        if (map_change) map_change(map_user, (void *)address, length, 0);
        views[i].live = 0;
        if (section->refs) section->refs--;
        if (!section->refs) destroy_section(section);
        if (error) *error = 0;
        return 1;
    }
    if (error) *error = NTW_ERR_ADDRESS;
    return 0;
}
int ntw_filemap_close(uint32_t handle, uint32_t *error) {
    ntw_section *section;
    uint32_t index;
    if (!lookup_handle(handle, &section, &index)) return 0;
    handles[index].live = 0;
    if (section->refs) section->refs--;
    if (!section->refs) destroy_section(section);
    if (error) *error = 0;
    return 1;
}
int ntw_filemap_duplicate(uint32_t source, int close_source, uint32_t *out, uint32_t *error) {
    ntw_section *section;
    uint32_t index;
    if (!out || !lookup_handle(source, &section, &index)) { if (error) *error = NTW_ERR_HANDLE; return 0; }
    section->refs++;
    if (!alloc_handle(handles[index].section, out)) {
        section->refs--;
        if (error) *error = NTW_ERR_NOMEM;
        return 0;
    }
    if (close_source) ntw_filemap_close(source, error);
    else if (error) *error = 0;
    return 1;
}
int ntw_filemap_query(uintptr_t address, uint32_t *base, uint32_t *allocation, uint32_t *allocation_protect,
                      uint32_t *region, uint32_t *state, uint32_t *protect) {
    uint32_t i;
    for (i = 0; i < NTW_MAP_SLOTS; ++i) if (sections[i].live && sections[i].base) {
        uintptr_t start = (uintptr_t)sections[i].base;
        uintptr_t end = start + sections[i].bytes;
        if (address < start || address >= end) continue;
        *base = (uint32_t)(address & ~(uintptr_t)4095u);
        *allocation = (uint32_t)start;
        *allocation_protect = sections[i].protect & 0xffu;
        *region = (uint32_t)(end - (address & ~(uintptr_t)4095u));
        *state = sections[i].reserved ? 0x2000u : 0x1000u;
        *protect = sections[i].reserved ? 0x01u : *allocation_protect;
        return 1;
    }
    return 0;
}
