#!/bin/bash

cmd1="$1"
list="$2"
cmd2="$3"
repo="$4"

progname="res_test"
progver="0.1"
sourcesList="/etc/apt/sources.list"

Version()
{
	echo "$progname v$progver"
	exit 0
}
Help()
{
	echo -e "Usege:\\n\\trus_test [-file <FILE> -repo <REPO>] [-v] [-h]"
	echo -e "\\t-file: file with package list"
	echo -e "\\t-repo: addres of repository"
	echo -e "\\t-h: show this help"
	echo -e "\\t-v: show version"
	exit 0
}

##parscmd()
if [ "x$cmd1" = "x-h"  ]; then
	Help
fi

if [ "x$cmd1" = "x-v"  ]; then
	Version
fi

if [[ "x$cmd1" = "x-file" ]] && [[ "x$cmd2" = "x-repo" ]] && [[ "x$list" != "x" ]] && [[ "x$repo" != "x" ]]; then
	echo "repo: $repo" #http://mirror.yandex.ru/debian/
	echo "file: $list"
else
	echo "Wrong!"
fi

cp "$sourcesList" "$sourcesList""orig"
#squeeze main non-free contrib
echo "deb $repo squeeze main non-free contrib" > "$sourcesList"
echo "deb-src $repo squeeze main non-free contrib" >> "$sourcesList"

apt-get update

cp "$sourcesList""orig" "$sourcesList"
exit 0


