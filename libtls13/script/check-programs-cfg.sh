#!/usr/bin/env sh

diff -u0 \
	<(find src example README.md -type f | sort) \
	<((echo -n 'for k in pairs(('; cat ../programs.cfg; echo ').libtls13.files) do print(k:match("[^/]+/[^/]+/(.+)")) end') | lua - | sort)
