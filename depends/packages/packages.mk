packages:=gmp backtrace libsodium

# Rust/Sapling toolchain packages (match Zcash layout).
# vendored_crates is a regular (host) package because it stages the offline
# crate registry into $(host_prefix)/vendored-sources, not into the native
# toolchain prefix. rustcxx installs the cxx.h header into host_prefix too.
# native_rust and native_cxxbridge are native packages (build-host tools).
kerrigan_packages := rustcxx vendored_crates
packages += $(kerrigan_packages)
native_packages += native_rust native_cxxbridge

boost_packages = boost

libevent_packages = libevent

qrencode_linux_packages = qrencode
qrencode_android_packages = qrencode
qrencode_darwin_packages = qrencode
qrencode_mingw32_packages = qrencode

qt_linux_packages:=qt expat libxcb xcb_proto libXau xproto freetype fontconfig libxkbcommon libxcb_util libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm
qt_freebsd_packages:=$(qt_linux_packages)
qt_android_packages=qt
qt_darwin_packages=qt
qt_mingw32_packages=qt

bdb_packages=bdb
sqlite_packages=sqlite

zmq_packages=zeromq

upnp_packages=miniupnpc
natpmp_packages=libnatpmp

multiprocess_packages = libmultiprocess capnp
multiprocess_native_packages = native_libmultiprocess native_capnp

usdt_linux_packages=systemtap
