#!/bin/sh

home_dir="$HOME/test_turlupov/"

Step1()
{
	dir="$1"
	maxnum="$2"
	for i in `seq 1 $maxnum`
	do
		mkdir "$home_dir""$i" 2>>/dev/null
		if [ "x$?" = "x1" ] ; then
			return 1
		fi
	done
	return 0
}

if [ -d $home_dir ] ; then
	rm -rf "$home_dir"*
else
	mkdir "$home_dir"
fi

#TODO check

## step 1 ##
echo "step 1.."
Step1 "$home_dir" 5
if [ "x$?" = "x1" ] ; then
	echo "step 1 FAILED"
	exit 1
fi
echo "step 1 PASSED"

return 0


echo "step 1.."
maxdir=5
for i in `seq 1 $maxdir`
do
	#echo "$i"
	mkdir "$home_dir""$i" 2>>/dev/null
	if [ "x$?" = "x1" ] ; then
		echo "step 1 FAILED"
		exit 1
	fi
done
echo "step 1 PASSED"
echo "step 2-4.."
maxfiles=100
for i in `ls $home_dir`
do
	#echo "in dir $home_dir$i"

	for j in `seq 1 $maxfiles`
	do
		filename="$home_dir$i/$j""_$i""k_"
		d=`date +%T_%d-%m-%Y` #hh:mm:ss_d-m-y
		#d= "`echo `"
		filename="$filename""$d"
		#echo "$filename"
		touch "$filename"
		dd if=/dev/urandom of=$filename bs=1k count=$i	1>/dev/null 2>/dev/null
	done
done
echo "step 2-4 PASSED"
echo "step 5.."
## step 5 ##
dir_for_cp="$home_dir""for_cp"
if [ -d $dir_for_cp ]
then
	rm -rf "$dir_for_cp"
fi
mkdir "$dir_for_cp"
if [ "x$?" = "x1" ] ; then
	echo "step 5 FAILED: mkdir fail"
	exit 1
fi
for i in `seq 1 $maxdir`
do
	cp -r "$home_dir$i" "$dir_for_cp"
	if [ "x$?" = "x1" ] ; then
		echo "step 5 FAILED: cp fail"
	exit 1
fi
done
echo "step 5 PASSED"
echo "step 6.."
## step 6 ##
dir_for_mv="$home_dir""for_mv"
if [ -d $dir_for_mv ]
then
	rm -rf "$dir_for_mv"
fi
mkdir "$dir_for_mv"
if [ "x$?" = "x1" ] ; then
	echo "step 6 FAILED: mkdir fail"
	exit 1
fi

mv "$dir_for_cp" "$dir_for_mv"
if [ "x$?" = "x1" ] ; then
	echo "step 6 FAILED: mv fail"
	exit 1
fi
echo "step 6 PASSED"

## step 7 ##
echo "step 7.."
for i in `seq 1 $maxdir`
do
	rm -rf "$home_dir""$i" 2>>/dev/null
	if [ "x$?" = "x1" ] ; then
		echo "step 7 FAILED"
		exit 1
	fi
done
echo "step 7 PASSED"
#echo "step 2-4.."
#expr 6 % 2

#TODO
## step 7 ##
echo "step 9.."
for i in `ls $dir_for_mv`
do
	echo "$i"
	#usedir=`expr $i % 2`
	if [ "x$usedir" = "x0" ] ; then
		echo "$i OK"
		#for j in `ls `
		#do

		#done

	else
		echo "$i not used"
	fi
done
echo "step 9 PASSED"





