cd exif_test

target_list=$('ls')
for target in $target_list; do
    cd $target/out/default/
    RESULT=$(ls fuzzer_stats 2>&-)
    if [[ "$RESULT" == "fuzzer_stats" ]]; then
        VAL=1
    else
        cd - &> /dev/null
        continue
    fi
    echo =============$target=============

    RESULT=$(cat fuzzer_stats | grep execs_per_sec)
    echo $RESULT

    RESULT=$(cat fuzzer_stats | grep corpus_found)
    echo $RESULT

    RESULT=$(cat fuzzer_stats | grep cycles_done)
    echo $RESULT

    RESULT=$(cat fuzzer_stats | grep saved_crashes)
    echo $RESULT

    cd - &> /dev/null
done


