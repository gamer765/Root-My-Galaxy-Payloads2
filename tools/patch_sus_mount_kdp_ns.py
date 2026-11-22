#!/usr/bin/env python3
"""Patch upstream sus_mount.c to support Samsung CONFIG_KDP_NS via BTF/kallsyms."""
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

# 1. Include btf_layout.h right after #include "mount.h"
anchor_inc = '#include "mount.h"'
assert anchor_inc in text, "mount.h include not found"
helpers = '''#include "mount.h"
#include "btf_layout.h"

/* Samsung CONFIG_KDP_NS moves struct vfsmount out of struct mount into a
 * KDP-protected slab, storing `struct vfsmount *mnt` in `struct kdp_mount`
 * right after `struct mount` and `struct mount *bp_mount` in `struct kdp_vfsmount`
 * right after `struct vfsmount`. Detect via BTF (or kallsyms fallback) at init. */
static bool sus_mount_kdp_ns;
static size_t sus_kdp_mount_mnt_off;
static size_t sus_kdp_vfsmount_bp_off;

static inline struct vfsmount *sus_mount_vfsmnt(struct mount *r)
{
    if (!r)
        return NULL;
    if (sus_mount_kdp_ns)
        return *(struct vfsmount **)((char *)r + sus_kdp_mount_mnt_off);
    return &r->mnt;
}

static inline struct mount *sus_real_mount(struct vfsmount *mnt)
{
    if (!mnt)
        return NULL;
    if (sus_mount_kdp_ns)
        return *(struct mount **)((char *)mnt + sus_kdp_vfsmount_bp_off);
    return real_mount(mnt);
}
'''
text = text.replace(anchor_inc, helpers, 1)

# 2. Replace all direct r->mnt / real_mount() accesses with KDP_NS-safe helpers
replacements = [
    ("r->mnt.mnt_sb->s_dev", "((sus_mount_vfsmnt(r) && sus_mount_vfsmnt(r)->mnt_sb) ? sus_mount_vfsmnt(r)->mnt_sb->s_dev : 0)"),
    ("r->mnt.mnt_root", "(sus_mount_vfsmnt(r) ? sus_mount_vfsmnt(r)->mnt_root : NULL)"),
    ("(r)->mnt.mnt_flags", "(sus_mount_vfsmnt(r) ? sus_mount_vfsmnt(r)->mnt_flags : 0)"),
    ("p.mnt = &r->mnt;", "p.mnt = sus_mount_vfsmnt(r);"),
    ("mnt_path.mnt = &r->mnt;", "mnt_path.mnt = sus_mount_vfsmnt(r);"),
    ("r = real_mount(mnt);", "r = sus_real_mount(mnt);"),
]
for old, new in replacements:
    assert old in text, f"Expected pattern not found: {old}"
    text = text.replace(old, new)

# 3. Guard d_path() calls against NULL mnt/dentry
text = text.replace(
    "dp = sus_mount_d_path(&p, buf, buflen);",
    "if (!p.mnt || !p.dentry)\n        return false;\n    dp = sus_mount_d_path(&p, buf, buflen);",
    1,
)
text = text.replace(
    "dp = sus_mount_d_path(&mnt_path, buf, PATH_MAX);",
    "if (!mnt_path.mnt || !mnt_path.dentry)\n                continue;\n            dp = sus_mount_d_path(&mnt_path, buf, PATH_MAX);",
    1,
)

# 4. Detect KDP_NS at the top of susfs_sus_mount_init()
find_sym = "susfs_find_kernel_symbol_exact" if "susfs_find_kernel_symbol_exact" in text else "find_kernel_symbol_exact"
init_anchor = "int susfs_sus_mount_init(void)\n{\n    int err;"
assert init_anchor in text, "susfs_sus_mount_init anchor not found"
init_detect = '''int susfs_sus_mount_init(void)
{
    int err;

    if (!susfs_btf_field_offset("kdp_mount", "mnt", "vfsmount*", &sus_kdp_mount_mnt_off) &&
        !susfs_btf_field_offset("kdp_vfsmount", "bp_mount", "mount*", &sus_kdp_vfsmount_bp_off)) {
        sus_mount_kdp_ns = true;
        SUSFS_LOGI("sus_mount: KDP_NS detected via BTF (kdp_mount.mnt=+0x%zx, kdp_vfsmount.bp_mount=+0x%zx)\\n",
                   sus_kdp_mount_mnt_off, sus_kdp_vfsmount_bp_off);
    } else if (__FIND_SYM__("kdp_mnt_alloc_vfsmount")) {
        sus_kdp_mount_mnt_off = sizeof(struct mount);
        sus_kdp_vfsmount_bp_off = sizeof(struct vfsmount);
        sus_mount_kdp_ns = true;
        SUSFS_LOGI("sus_mount: KDP_NS detected via kallsyms (fallback +0x%zx / +0x%zx)\\n",
                   sus_kdp_mount_mnt_off, sus_kdp_vfsmount_bp_off);
    }'''.replace("__FIND_SYM__", find_sym)
text = text.replace(init_anchor, init_detect, 1)

assert "r->mnt." not in text, "Remaining r->mnt. access!"
assert text.count("&r->mnt") == 1, f"Expected 1 &r->mnt (in helper), found {text.count('&r->mnt')}"

path.write_text(text, encoding="utf-8")
print(f"Patched {path} for Samsung CONFIG_KDP_NS cleanly (sym={find_sym}).")
