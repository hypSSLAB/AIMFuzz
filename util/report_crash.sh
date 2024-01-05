mkdir crash_report

export AFL_USE_QASAN=1
BINARY_NAME=exif

echo "$(ls ./crash_example)" > tmp_output

i=0
while read line ; do

	exec > ./crash_report/$line
	exec 2>&1
	
	afl-qemu-trace $BINARY_NAME ./crash_example/$line
	((i+=1))
done < tmp_output

rm -rf tmp_output



