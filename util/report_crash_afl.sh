mkdir crash_report_afl

export AFL_USE_QASAN=1
BINARY_NAME=exif

echo "$(ls ./crash_example_afl)" > tmp_output

i=0
while read line ; do

	exec > ./crash_report_afl/$line
	exec 2>&1

	echo "./crash_report_afl/"$line
	echo $line

	echo ""

	afl-qemu-trace $BINARY_NAME ./crash_example_afl/$line
	((i+=1))
done < tmp_output

rm -rf tmp_output



