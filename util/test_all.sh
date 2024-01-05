CNT=25
i=1
while read line || [ -n "$line" ] ; do
	line=$(echo $line | awk -F "," '{print$1}')
	./run.sh $line &
	sleep 5
	
	if [ $i -eq $CNT ]
	then
		break
	fi	
	((i+=1))
done < taint_list
