
Debian
====================
This directory contains files used to package kerrigand/kerrigan-qt
for Debian-based Linux systems. If you compile kerrigand/kerrigan-qt yourself, there are some useful files here.

## kerrigan: URI support ##


kerrigan-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install kerrigan-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your kerrigan-qt binary to `/usr/bin`
and the `../../share/pixmaps/kerrigan128.png` to `/usr/share/pixmaps`

kerrigan-qt.protocol (KDE)

