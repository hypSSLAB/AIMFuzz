# AIMFuzz, We will update it soon
***
### install AFL++
***
https://github.com/AFLplusplus/AFLplusplus
***
### AIMF Install

***
cd ./libdft64/src/ 
<br/>
make clean 
<br/>        
make 
<br/>               
cd./libdft64/tools/  
<br/>
make clean          
<br/>
make                
***


### Target Fyunction Scoring
***
pin -t /root/ATFF/libdft64/tools/obj-intel64/track.so -- <binary> <binary option> ./in/input_file

[Example] pin -t /root/ATFF/libdft64/tools/obj-intel64/track.so -- ./tiffinfo_404 -D -j -c -r -s -w ./in/input_file 
#### You can use script
./function_scoring_test.sh
[Input] The input path must be ./in/input_file (Important) You need to change input filename-->input_file
[Script] /root/ATFF/test/fuzzing_libexif/scoring_test/ and /root/ATFF/test/fuzzing_libtiff/ have sample scripts

[Experiment] Coefficient w can be changed to (0, 0.01, 0.1, 0.5, 1) and logbase can be changed to (0, 2, 4, 8, 16). Of course, 0 logbase does not exist, but 0 means adding points without taking log.

[Binary Option]
libexif	
<br/>
./test-mnote_0619 ./in/input_file
<br/>
libtiff	./tiffinfo_404 -D -j -c -r -s -w ./in/input_file

[Scoring Result]
rank_result_[Target_Function_Name]
***
### Target Function Identifying & Locating
***
pin -t /root/ATFF/libdft64/tools/obj-intel64/track.so <target_function> -- <binary> <binary option> ./in/input_file
[Example] pin -t /root/ATFF/libdft64/tools/obj-intel64/track.so pcap_offline_read -- ./tiffinfo_404 -D -j -c -r -s -w
<br/>
./in/input_file
<br/>
##### You can use script
./memory_scanning_test.sh

[Identify Result]
result_identifying_[Target_Function_Name]
result_locating_[Target_Function_Name]

***
### AIMFuzz Fuzzing
***
cd ./test/fuzzing_libexif/exif_0614_automated_persistent_mutator_test
<br/>
./run_in_memory_fast.sh [Target_Function_NAME] [ID]
[Example] ./run_in_memory_fast.sh exif_loader_get_data 1
***

### AIMFuzz Antifuzz Fuezzing
***
cd ./test/fuzzing_libexif/antifuzz/persistent/hook
<br/>
make clean
<br/>
make
<br/>
cd ..
./run_in_memory_fast.sh [Target_Function_NAME] [ID]
***
