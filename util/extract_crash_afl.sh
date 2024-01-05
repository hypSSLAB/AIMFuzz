CUR_DIR=$PWD
CRASH_DIR=$CUR_DIR/crash_example_afl
PREPROCESS=$CUR_DIR/preprocess

mkdir $CRASH_DIR
cd exif_afl_test

target_list=$('ls')
for target in $target_list; do
    echo =============$target=============
    cd $target/out/default/crashes

    crash_list=$('ls')
    for crash in $crash_list; do
        #echo $crash

        if [ $crash == "README.txt" ]; then
            var=1
        elif [ -z "$crash" ]; then
            var=1
        else
            cp ./$crash $CRASH_DIR/$target"_"$crash
            echo $crash
        fi       

    done
    cd - &> /dev/null
done


