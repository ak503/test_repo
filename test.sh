#!/bin/sh

home_dir="$HOME/test_turlupov"
dir_for_cp="$HOME/test_turlupov/for_cp"
dir_for_mv="$HOME/test_turlupov/for_mv"

maxdir=5
maxfiles=10

if [ -d $home_dir ] ; then
	rm -rf "$home_dir"
fi
mkdir "$home_dir"


######## step 1 ########
echo "Step 1:"
for i in `seq 1 $maxdir`
do
	#echo "$i"
	mkdir "$home_dir"/"$i"
	if [ "x$?" = "x1" ] ; then
		echo "\tFAILED"
		exit 1
	fi
done
echo "\tPASSED"
########################

######## step 2 ########

#echo "Step 2:"
#for i in `ls $home_dir` ; do
#	for j in `seq 1 $maxfiles` ; do
#		touch $home_dir/$i/$j
#		if [ "x$?" = "x1" ] ; then
#			echo "\tFAILED touch"
#			exit 1
#		fi
#		dd if=/dev/urandom of=$home_dir/$i/$j bs=100 count=1 1>/dev/null 2>/dev/null
#		if [ "x$?" = "x1" ] ; then
#			echo "\tFAILED dd"
#			exit 1
#		fi
#	done
#done
#echo "\tPASSED"

########################
#return 0




####### step 2-4 #######
echo "Step 2-4:"
for i in `ls $home_dir` ; do

	for j in `seq 1 $maxfiles` ; do
		filename="$home_dir/$i/$j""_$i""k_"
		d=`date +%T_%d-%m-%Y` #hh:mm:ss_d-m-y
		filename="$filename""$d"
		dd if=/dev/urandom of=$filename bs=1k count=$i	1>/dev/null 2>/dev/null
	done
done
echo "\tPASSED"
########################

######## step 5 ########
echo "Step 5:"
if [ -d $dir_for_cp ] ; then
	rm -rf "$dir_for_cp"
fi

mkdir "$dir_for_cp"
if [ "x$?" = "x1" ] ; then
	echo "\tFAILED: mkdir fail"
	exit 1
fi

for i in `seq 1 $maxdir` ; do
	cp -r "$home_dir/$i" "$dir_for_cp"
	if [ "x$?" = "x1" ] ; then
		echo "\tFAILED: cp fail"
		exit 1
	fi
done

echo "\tPASSED"
########################

######## step 6 ########
echo "Step 6:"
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
#return 0
#echo "step 2-4.."
#expr 6 % 2

#TODO
######## step 7 ########
echo "Step 9:"
for i in `ls $dir_for_mv/for_cp`
do
	#echo "$i"
	usedir=`expr $i % 2`
	if [ "x$usedir" = "x0" ] ; then
		#echo "$i use"
		for j in `ls $dir_for_mv/for_cp/$i` ; do
			#echo "name= $j"
			b=`echo "$j" |sed  s/^[0-9]*/""/`
			#echo "b= $b"
			name=`echo "$j" |sed  s/"$b"/""/`
			#echo "name2= $name"
			delfile=`expr $name % 2`
			if [ "x$delfile" != "x0" ] ; then
				rm -rf  $dir_for_mv/for_cp/$i/$j
			fi
		done
	fi
done
echo "\tPASSED"
########################





