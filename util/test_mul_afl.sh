for ((var=0 ; var < $1 ; var++));
do
	./run_afl.sh $var &
	sleep 1
done
