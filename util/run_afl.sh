BINARY_NAME=exif

mkdir $BINARY_NAME"_afl_test"

cd $BINARY_NAME"_afl_test"

mkdir "ID_"$1

cd "ID_"$1

mkdir in
mkdir out

cp ../../in/input_file ./in/input_file
cp ../../$BINARY_NAME ./

afl-fuzz -V 86400 -i ./in -o ./out -- ./$BINARY_NAME @@ &

