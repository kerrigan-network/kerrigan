package=sqlite
$(package)_version=3500200
$(package)_download_path=https://sqlite.org/2025/
$(package)_file_name=sqlite-autoconf-$($(package)_version).tar.gz
$(package)_sha256_hash=84a616ffd31738e4590b65babb3a9e1ef9370f3638e36db220ee0e73f8ad2156

# SQLite 3.50.x switched its build system from autoconf to autosetup, which
# has a different (and stricter) command-line vocabulary. Several flags that
# work fine for autoconf packages are unknown to autosetup and cause a hard
# error ("Unknown option ..."). Notably the shared $(package)_autoconf macro
# in depends/funcs.mk hardcodes --with-pic, which autosetup rejects.
#
# We therefore:
#   * Do NOT use $(package)_autoconf -- call ./configure directly.
#   * Drop --enable-option-checking, --disable-dynamic-extensions and the
#     --disable-{rtree,fts4,fts5} flags (those extensions are now opt-in;
#     the default is already "off", so the explicit disable would be both
#     unknown and redundant).
#   * Keep --disable-shared / --disable-readline / --disable-load-extension
#     / --disable-math, which autosetup still accepts.
#   * -fPIC is no longer needed on the configure line (static lib build),
#     but we pass it via CFLAGS/CXXFLAGS to keep behavior identical to the
#     previous (autoconf-driven) recipe.

define $(package)_set_vars
$(package)_config_opts=--disable-shared --disable-readline --disable-load-extension
$(package)_config_opts+= --build=$(BUILD) --host=$($($(package)_type)_host)
$(package)_config_opts+= --prefix=$($($(package)_type)_prefix)
# We avoid using `--enable-debug` because it overrides CFLAGS, a behavior we want to prevent.
$(package)_cppflags_debug += -DSQLITE_DEBUG
$(package)_cppflags+=-DSQLITE_DQS=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_OMIT_DEPRECATED
$(package)_cppflags+=-DSQLITE_OMIT_SHARED_CACHE -DSQLITE_OMIT_JSON -DSQLITE_LIKE_DOESNT_MATCH_BLOBS
$(package)_cppflags+=-DSQLITE_OMIT_DECLTYPE -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_OMIT_AUTOINIT
$(package)_cflags+=-fPIC
$(package)_cxxflags+=-fPIC
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub .
endef

define $(package)_config_cmds
  ./configure $$($(package)_config_opts) \
    CC="$$($(package)_cc)" \
    CXX="$$($(package)_cxx)" \
    AR="$$($(package)_ar)" \
    RANLIB="$$($(package)_ranlib)" \
    NM="$$($(package)_nm)" \
    CFLAGS="$$($(package)_cflags) $$($(package)_cppflags)" \
    CXXFLAGS="$$($(package)_cxxflags) $$($(package)_cppflags)" \
    CPPFLAGS="$$($(package)_cppflags)" \
    LDFLAGS="$$($(package)_ldflags)"
endef

define $(package)_build_cmds
  $(MAKE) libsqlite3.a
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install-lib install-headers install-pc
endef
