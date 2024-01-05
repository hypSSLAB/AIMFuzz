TARGET_NAME=$1
TARGET_ID=$2

# Modification Needed!
BINARY_NAME="exif"
INPUT_PATH="/root/ATFF/test/fuzzing_libexif/in"
BINARY_PATH="/root/ATFF/test/fuzzing_libexif/exif"

PLUGIN_PATH="/root/ATFF/tcg_plugin/libregion.so"
HOOK_PATH="/root/ATFF/afl_persistent/hook.so"
PIN_TOOL_PATH="/root/ATFF/libdft64/tools/obj-intel64/track.so"

mkdir $BINARY_NAME"_test"
cd $BINARY_NAME"_test"

mkdir $TARGET_NAME"_"$TARGET_ID
cd $TARGET_NAME"_"$TARGET_ID

cp $BINARY_PATH ./

mkdir in
cp $INPUT_PATH/* ./in

mkdir out

#extract tag info
pin -t $PIN_TOOL_PATH $TARGET_NAME -- ./$BINARY_NAME ./in/input_file

RESULT=$(ls taint_tag)
echo $RESULT
if [[ "$RESULT" == "taint_tag" ]]; then
	echo "exist"
else
	echo "not exist"
	cd ..
	rm -rf $TARGET_NAME"_"$TARGET_ID
	exit 1
fi

# extract main & target address
BASE_ADDR=0

TARGET_ADDR=$(nm $BINARY_NAME | grep -w "$TARGET_NAME$" | awk '{print $1}')
TARGET_ADDR=$((0x$TARGET_ADDR + 0x$BASE_ADDR))
TARGET_ADDR=0x$(printf '%x' $TARGET_ADDR)
echo "TARGET ADDR : $TARGET_ADDR"

MAIN_ADDR=$(nm $BINARY_NAME | grep -w "main$" | awk '{print $1}')
MAIN_ADDR=$((0x$MAIN_ADDR + 0x$BASE_ADDR))
MAIN_ADDR=0x$(printf '%x' $MAIN_ADDR)
echo "MAIN ADDR : $MAIN_ADDR"

# set env variable
#export AFL_DEBUG=1
#export PATH_COVERAGE=1

export AFL_CUSTOM_MUTATOR_LIBRARY=/root/ATFF/AFLplusplus/custom_mutators/libfuzzer_taint/libfuzzer-mutator.so
export AFL_CUSTOM_MUTATOR_ONLY=1

export AFL_USE_QASAN=1
export AFL_QEMU_PERSISTENT_GPR=1
export AFL_QEMU_PERSISTENT_MEM=1
export AFL_QEMU_PERSISTENT_EXITS=1
export AFL_QEMU_PERSISTENT_ADDR=$TARGET_ADDR
export TARGET_BINARY_PATH="$BINARY_PATH"_test/$TARGET_NAME"_"$TARGET_ID/$BINARY_NAME
export TCG_PLUGIN_PATH=$PLUGIN_PATH
export QEMU_PLUGIN=$PLUGIN_PATH,arg=$TARGET_ADDR,arg=$MAIN_ADDR
export AFL_QEMU_PERSISTENT_HOOK=$HOOK_PATH

mkdir ./out/default
#mkdir ./out/123
cp ./in/input_file ./out/default/.cur_input
#cp ./in/input_file ./out/123/.cur_input

#afl-fuzz -Q -i ./in -o ./out -S 123 -- ./$BINARY_NAME @@ /dev/null
afl-fuzz -Q -i ./in -o ./out -V 86400 -- ./$BINARY_NAME @@


