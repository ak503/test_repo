#!/bin/sh

home_dir="$HOME/test_turlupov/"
maxdir=5
maxfiles=100

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
#echo "step 1.."
#Step1 "$home_dir" 5
#if [ "x$?" = "x1" ] ; then
#	echo "step 1 FAILED"
#	exit 1
#fi
#echo "step 1 PASSED"

#return 0

######## step 1 ########
echo "Step 1:"
for i in `seq 1 $maxdir`
do
	#echo "$i"
	mkdir "$home_dir""$i" 2>>/dev/null
	if [ "x$?" = "x1" ] ; then
		echo "\tFAILED"
		exit 1
	fi
done
echo "\tPASSED"
########################

####### step 2-4 #######
echo "Step 2-4:"
for i in `ls $home_dir`
do
	#echo "in dir $home_dir$i"

	for j in `seq 1 $maxfiles`
	do
		filename="$home_dir$i/$j""_$i""k_"
		d=`date +%T_%d-%m-%Y` #hh:mm:ss_d-m-y
		filename="$filename""$d"
		#touch "$filename"
		dd if=/dev/urandom of=$filename bs=1k count=$i	1>/dev/null 2>/dev/null
	done
done
echo "\tPASSED"
########################

######## step 5 ########
echo "Step 5:"
dir_for_cp="$home_dir""for_cp"

if [ -d $dir_for_cp ] ; then
	rm -rf "$dir_for_cp"
fi

mkdir "$dir_for_cp"
if [ "x$?" = "x1" ] ; then
	echo "\tFAILED: mkdir fail"
	exit 1
fi

for i in `seq 1 $maxdir` ; do
	cp -r "$home_dir$i" "$dir_for_cp"
	if [ "x$?" = "x1" ] ; then
		echo "\tFAILED: cp fail"
		exit 1
	fi
done

echo "\tPASSED"
########################

######## step 6 ########
echo "Step 6:"
dir_for_mv="$home_dir""for_mv"
if [ -d $dir_for_mv ] ; then
	rm -rf "$dir_for_mv"
fi

mkdir "$dir_for_mv"
if [ "x$?" = "x1" ] ; then
	echo "\tFAILED: mkdir fail"
	exit 1
fi

mv "$dir_for_cp" "$dir_for_mv"
if [ "x$?" = "x1" ] ; then
	echo "\tFAILED: mv fail"
	exit 1
fi
echo "\tPASSED"
########################

######## step 7 ########
echo "Step 7:"
for i in `seq 1 $maxdir`
do
	rm -rf "$home_dir""$i" 2>>/dev/null
	if [ "x$?" = "x1" ] ; then
		echo "\tFAILED"
		exit 1
	fi
done
echo "\tPASSED"
########################
return 0
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





