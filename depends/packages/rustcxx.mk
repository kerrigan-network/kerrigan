package=rustcxx
# Inherit source tarball and hash from native_cxxbridge. Use := so the
# expansion happens now (while $(package) is still rustcxx and the
# native_cxxbridge_* values refer to their recursive RHS without $(package)
# bleeding through from a later-included file).
$(package)_version:=$(native_cxxbridge_version)
$(package)_file_name:=native_cxxbridge-$(native_cxxbridge_version).tar.gz
$(package)_sha256_hash:=$(native_cxxbridge_sha256_hash)

define $(package)_fetch_cmds
  $(call native_cxxbridge_fetch_cmds,native_cxxbridge)
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include/rust && \
  cp include/cxx.h $($(package)_staging_prefix_dir)/include/rust
endef
