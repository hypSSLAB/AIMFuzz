for ((var=0 ; var < $2 ; var++));
do
	./run.sh $1 $var &
	sleep 1
done
