package=libsodium
$(package)_version=1.0.20
$(package)_download_path=https://download.libsodium.org/libsodium/releases/
$(package)_file_name=libsodium-$($(package)_version).tar.gz
$(package)_sha256_hash=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19

define $(package)_set_vars
$(package)_config_opts += --disable-shared --enable-static
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm lib/*.la
endef
