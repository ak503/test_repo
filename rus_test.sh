#!/bin/bash

cmd1="$1"
list="$2"
cmd2="$3"
repo="$4"

progname="res_test"
progver="0.1"

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

if [ "x$cmd1" = "x-h"  ]; then
	Help
fi

if [ "x$cmd1" = "x-v"  ]; then
	Version
fi

if [[ "x$cmd1" = "x-file" ]] && [[ "x$cmd2" = "x-repo" ]] && [[ "x$list" != "x" ]] && [[ "x$repo" != "x" ]]; then
	echo "repo: $repo"
	echo "file: $list"
else
	echo "Wrong!"
fi
exit 0


