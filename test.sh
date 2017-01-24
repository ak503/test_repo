#!/bin/sh

maxDir=5
maxFiles=10
home_dir="$HOME/test_turlupov"
step5DirName="for_cp"
step5DirPath="$home_dir/$step5DirName"

step6DirName="for_mv"
step6DirPath="$home_dir/$step6DirName"

#temp dir.
step71DirName=".tmp"
step71DirPath="$home_dir/$step71DirName"

#echo ""
if [ -d $home_dir ] ; then
	rm -rf "$home_dir"
fi
mkdir "$home_dir"

CheckResult()
{
	local stepNumber="$1"
	local stepStatus="$2"
	local errorMessage="$3"
	if [ "x$stepStatus" = "x1" -o "x$stepStatus" = "x2" ] ; then
		echo "\tTEST FAILED. Err code $stepStatus"
		exit 1
	else
		echo "\tTEST PASSED"
	fi
}

Step1(){
	local rootDir="$1"
	local numDirs="$2"
	local i=""

	for i in `seq 1 $numDirs` ; do
		mkdir "$rootDir"/"$i" 2>/dev/null
		if [ "x$?" = "x1"  ] ; then
			return 1
		fi
	done
	return 0
}


Step2_4(){
	local rootDir="$1"
	local numFiles="$2"
	local d="", i="", j=""

	for i in `ls $rootDir` ; do
		for j in `seq 1 $numFiles` ; do
			filename=$j"_"$i"k_"

			d=`date +%T_%d-%m-%Y` #hh:mm:ss_d-m-y

			fileName="$filename""$d" #num_size_hh:mm:ss_d-m-y
			filePath="$rootDir"/"$i"/"$fileName"

			dd if=/dev/urandom of="$filePath" bs=1k count=$i 1>/dev/null 2>/dev/null
			if [ "x$?" = "x1" ] ; then
				return 1
			fi
		done
	done
	return 0
}

Step5()
{
	local rootDir="$1"
	local numDirs="$2"
	local newDir="$3"
	local i=""

	mkdir "$newDir" 2>/dev/null
	if [ "x$?" = "x1" ] ; then
		return 1
	fi

	for i in `seq 1 $numDirs` ; do
		cp -r "$rootDir/$i" "$newDir" 2>/dev/null
		if [ "x$?" = "x1" ] ; then
			return 2
		fi
	done
	return 0
}
Step6()
{
	local srcDir="$1"
	local dstDir="$2"

	mkdir "$dstDir"
	if [ "x$?" = "x1" ] ; then
		return 1
	fi

	mv "$srcDir" "$dstDir" 2>/dev/null
	if [ "x$?" = "x1" ] ; then
		return 2
	fi
	return 0
}

Step7_2()
{
	local rootDir="$1"
	local numDirs="$2"
	local i=""

	for i in `seq 1 $numDirs` ; do
		rm -r "$rootDir"/"$i" 2>/dev/null
		if [ "x$?" = "x1" ] ; then
			return 1
		fi
	done
	return 0
}

Step8()
{
	local tmpDir="$1"
	local numDirs="$2"
	local dataDir="$3"
	local rez="",i="",j="", name="",originfile="", movedfile=""

	for i in `seq 1 $numDirs` ; do
		for j in `ls $tmpDir/$i` ; do  #get name
			name="$j"
			originfile="$tmpDir/$i/$j"
			movedfile="$dataDir/$i/$j"
			#echo "o= $originfile"
			#echo "m= $movedfile"
			diff -N $originfile $movedfile 1>/dev/null 2>/dev/null
			rez="$?"

			if [ "x$rez" = "x1" -o "x$rez" = "x2" ] ; then
				return $rez
			fi
		done
	done
	return 0
}

Step9(){
	local dataDir="$1"
	local i="", j="", usedir="", tmp="", name="",delfile=""

	for i in `ls $dataDir` ; do
		usedir=`expr $i % 2`
		if [ "x$usedir" = "x0" ] ; then #select dir $i
			for j in `ls $dataDir/$i` ; do		#j = 199_5k_18:27:25_24-01-2017
				tmp=`echo "$j" |sed  s/^[0-9]*/""/`  #tmp= _5k_18:27:25_24-01-2017
				name=`echo "$j" |sed  s/"$tmp"/""/`  #name= 199
				delfile=`expr $name % 2`
				if [ "x$delfile" != "x0" ] ; then
					rm -r $dataDir/$i/$j 2>/dev/null
					if [ "x$?" = "x1" ] ; then
						return 1
					fi
				fi
			done
		fi
	done


	return 0
}

#create original dirs
echo "Step 1:\n\tCreate $maxDir dirs in $home_dir"
Step1 "$home_dir" "$maxDir"
CheckResult "1" "$?"

#create files in original dirs
echo "Step 2_4:\n\tCreate $maxFiles files in each dir"
Step2_4 "$home_dir" "$maxFiles"
CheckResult "2_4" "$?"

#copy original dirs to step5Dir
echo "Step 5:\n\tCopy each dirs from $home_dir to $step5DirPath"
Step5 "$home_dir" "$maxDir" "$step5DirPath"
CheckResult "5" "$?"

#move step5Dir to step6Dir (total_dir = "step6Dir/step5Dir/")
echo "Step 6:\n\tMove $step5DirPath to $step6DirPath"
Step6 "$step5DirPath" "$step6DirPath"
CheckResult "6" "$?"

#copy original dirs to temp dir
echo "Step 7.1:\n\tCopy original dirs to temp dir"
Step5 "$home_dir" "$maxDir" "$step71DirPath"
CheckResult "7.1" "$?"

#delete original dirs
echo "Step 7.2:\n\tDelete original dirs"
Step7_2 "$home_dir" "$maxDir"
CheckResult "7.2" "$?"

#diff files in temp dir and files in step6Dir (total_dir)
echo "Step 8: diff files from temp dirs and $step6DirPath/$step5DirName"
Step8 "$step71DirPath" "$maxDir" "$step6DirPath/$step5DirName"
CheckResult "8" "$?"

# del fileN1, fileN3, fileN5 ... in dir2, dir4
echo "Step 9:\n\tDelete some files from $step6DirPath/$step5DirName"
Step9 "$step6DirPath/$step5DirName"
CheckResult "9" "$?"

# delete tempdir
rm -r "$step71DirPath" 2>/dev/null

exit 0
