package=vendored_crates
$(package)_version=1.1.1
$(package)_download_path=file://$(BASEDIR)/sources/
$(package)_file_name:=vendored-crates-$($(package)_version).tar.gz
$(package)_sha256_hash=adddf4e5e9ed37296699da45c862db80b9f231057203d9450dd46d4115792624
$(package)_build_subdir=.

# This package does not pull crates from the network. The tarball is produced
# ahead of time by `download-crates.sh` and shipped in depends/sources/, which
# is also where $(package)_source_dir (= $(SOURCES_PATH)) resolves to. So the
# "fetch" step is simply a hash check on the already-present tarball.

define $(package)_fetch_cmds
  test -f $$($(package)_source_dir)/$($(package)_file_name) \
    || { echo "error: $($(package)_file_name) is missing from $$($(package)_source_dir)." >&2; \
         echo "hint:  run ./download-crates.sh at the repo root to regenerate it." >&2; exit 1; } && \
  echo "$($(package)_sha256_hash)  $$($(package)_source_dir)/$($(package)_file_name)" \
    > $$($(package)_source_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $$($(package)_source_dir)/.$($(package)_file_name).hash
endef

# Extract into the package's extract_dir. The tarball's top-level directory
# after extraction is `vendor/`, which we copy to `vendored-sources/` at
# stage time so the main build's .cargo/config.toml (which points at
# $(RUST_VENDORED_SOURCES) = $(depends_prefix)/vendored-sources) finds it.
define $(package)_extract_cmds
  mkdir -p $$($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $$($(package)_source)" > $$($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $$($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_TAR) --no-same-owner -xf $$($(package)_source) -C $$($(package)_extract_dir)
endef

# Nothing to preprocess; the tarball is already the vendor tree.
define $(package)_preprocess_cmds
  true
endef

# "Build" is a no-op: cargo vendor produces source only.
define $(package)_build_cmds
  true
endef

# Stage into $(host_prefix)/vendored-sources/ to match RUST_VENDORED_SOURCES
# ($(depends_prefix)/vendored-sources) set in depends/config.site.in. This
# keeps the offline crate registry at a single canonical location referenced
# by both depends/funcs.mk::vendor_crate_deps and src/Makefile.am's
# .cargo/config.toml writer.
define $(package)_stage_cmds
  mkdir -p $$($(package)_staging_prefix_dir) && \
  cp -a $$($(package)_extract_dir)/vendor \
        $$($(package)_staging_prefix_dir)/vendored-sources
endef
