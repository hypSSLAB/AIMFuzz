#include "taint_info.h"

string target2find;
int TAINT_MODE;
int seq_num;
int read_seq_num;

extern int monitor_taint_flag;

uint64_t input_file_size;

// BBL Info
map<uint64_t, uint64_t> bbl_list;

// Tag Info
map<tag_t, char> tagVal;

// Tainted Memory Info
map<uint64_t, tag_t> before_taint_mem_list;
map<uint64_t, tag_t> taint_mem_list;

// Tainted Instruction Info
FuncNode *root_node;
FuncNode *cur_node;

map<string, FuncNode *> taint_func_ptr;
map<string, double> taint_func;
map<string, int> taint_seq;
map<string, int> taint_depth;

map<string, int> func_called;

vector<ScoreNode *> func_score_list;

// scoring
double callee_weight = 0.1;
int taint_weight = 2;

// Tag Info
void insert_tagVal(tag_t tag, char val) {
    if (tag > 100000000) {
        return;
    }

    if (tagVal.insert(make_pair(tag, val)).second == false) {
        //cout << "Insertion Failed. Key was present" << endl;
    }
}

void print_tagVal() {
    fstream new_file;
    new_file.open("tag_value", ios::out);
    if (!new_file) {
        cout << "file creation failed" << endl;
        return;
    }

    //cout << "==========tag val==========" << endl;
    uint64_t i = 0;
    for (auto iter = tagVal.begin(); iter != tagVal.end(); iter++) {
        if ((*iter).first == 0) continue;
        if ((*iter).first > 100000000) continue;
        
        if (i >= input_file_size) {
            break;    
        }
        //cout << "[tag] : " << dec << (*iter).first << ", [val] : " << (*iter).second << endl;
        new_file << dec << (*iter).first << "," << hex << (((unsigned int)((*iter).second)) & 0xff) << endl;
        i++;
    }

    new_file.close(); 
}

// Tainted Memory Info
void insert_taint_mem_info(int ins_type, ADDRINT addr, char value, tag_t tag, string func_name) {
    tag_t cur_tag;
    char cur_val;

    if (ins_type == XFER_R2M || ins_type == ARITH_R2M) {
        return;
    }

    // pollution mode
    if (tag == (tag_t)-1) {
        if (cur_node != NULL) {
            cur_node->modified_tag_used += 1;
        }
        
        return;
    }
    cur_node->origianl_tag_used += 1;

    if (TAINT_MODE == TAINT_REGION_FINDING && taint_logging == 0) {
        if (taint_logging == 0 || before_taint_mem_list[addr] == 0) {
            return;
        }
    }

    if (tag == 0 || addr == 0)  {
        return;
    }

    cur_tag = tagmap_getb(addr);
    if (cur_tag != tag) {
        return;
    }

    cur_val = tagVal[tag];
    if (cur_val != value) {
        return;
    }

    if (taint_mem_list[addr] != 0) {
        return;
    }
    cur_node->taint_inst_used = 1; 
    taint_mem_list[addr] = before_taint_mem_list[addr];
}

void log_before_taint_mem_list() {
    FILE *pFile = NULL;
	char map_buf[1024];
	char *map_ptr;
    unsigned long cur_addr;

    // find tainted memory address 
    pFile = fopen("/proc/self/maps", "r");

	while(fgets(map_buf, 1024, pFile)) {
		char *addr1;
		char *addr2;

		unsigned long min, max;
		int i;

		map_ptr = strtok(map_buf, " ");
		
		i = 0;
		while (1) {
			if (map_ptr[i] == '-') {
				map_ptr[i] = '\0';
				addr1 = map_ptr;
				addr2 = map_ptr+i+1;
				break;
			}
			i++;
		}
		min = strtol(addr1, NULL, 16);
		max = strtol(addr2, NULL, 16);

        cur_addr = min;
        while (cur_addr < max) {
            tag_t cur_tag = tagmap_getb(cur_addr);

            if (cur_tag != 0 && cur_tag != ((tag_t)-1)) {
                before_taint_mem_list[cur_addr] = cur_tag;
            }

            cur_addr++;
        }
	}
    cout << "before taint mem list size : " << before_taint_mem_list.size() << endl;

	fclose(pFile);
}

void print_func_taint_mem_info() {
    uint64_t prev_addr;
    uint64_t cur_addr;
    tag_t tag;
    fstream new_file;
    
    if (!before_taint_mem_list.size()) {
        cout << "no taint tag" << endl;
        return;
    }

    new_file.open("taint_tag", ios::out);
    if (!new_file) {
        cout << "file creation failed" << endl;
        return;
    }
    cout << "===============taint tag================" << endl;
    prev_addr = 0;
    for (auto iter_map = before_taint_mem_list.begin(); iter_map != before_taint_mem_list.end(); iter_map++) {        
        cur_addr = iter_map->first;
        tag = iter_map->second;

        if (tag == 0) {
            continue;
        }

        if (prev_addr == 0) {
            cout << "[" << hex << cur_addr << "] : " << dec << tag << endl;
            new_file << dec << tag;
        } else if (prev_addr+1 == cur_addr) {
            //cout << "[" << hex << cur_addr << "] : " << dec << tag << endl;
            new_file << " " << dec << tag;
        } else {
            cout << "[" << hex << cur_addr << "] : " << dec << tag  << endl;
            new_file << endl;
            new_file << dec << tag;
        }
        prev_addr = cur_addr;
    }
    new_file.close();
}

// Tainted Instruction Info
void insert_taint_inst(string func_name, uint64_t addr) {
    uint64_t bbl_addr;

    //printf("insert taint inst\n");
    if (cur_node == NULL) {
        // Cannot reach here
        //printf("error at insert taint inst\n");
        return;
    }

    auto low_iter = bbl_list.lower_bound(addr);
    if (low_iter == bbl_list.end()) {
        // cannot reach here
        cout << "=====================================" << endl;
        cout << "bbl list none" << endl;
        return;
    } else if (low_iter == bbl_list.begin()) {
        bbl_addr = low_iter->first;
        /*
        cout << "=====================================" << endl;
        cout << "bbl list first" << endl;
        cout << "BBL : " << hex << low_iter->first << " ~ " << low_iter->second << endl;
        */
    } else {
        if (low_iter->first == addr) {
            bbl_addr = addr;
        } else {
            auto prev_iter = low_iter;
            prev_iter--;
            if (prev_iter->second < addr) {
                // cannot reach here
                cout << "bbl error" << endl;
            }
            bbl_addr = prev_iter->first;
        }/*
        auto prev_iter = low_iter;
        prev_iter--;
        cout << "=====================================" << endl;
        cout << "addr : " << hex << addr << endl;
        cout << "prev : " << prev_iter->first << " ~ " << prev_iter->second << endl;
        cout << "low : " << low_iter->first << " ~ " << low_iter->second << endl;
        */
    }
    //cur_node->taint_inst[addr] = 1;
    //cout << "if " << endl;
    //cur_node->taint_inst[bbl_addr][addr]++;
    
    if (cur_node->taint_inst.find(bbl_addr) == cur_node->taint_inst.end()) {
        cur_node->taint_inst[bbl_addr][addr] = 1;
    } else {
        if (cur_node->taint_inst[bbl_addr].find(addr) == cur_node->taint_inst[bbl_addr].end()) {
            cur_node->taint_inst[bbl_addr][addr] = 1;
        } else {
            cur_node->taint_inst[bbl_addr][addr]++;
        }
    }
    /*
    if (cur_node->taint_inst.find(addr) == cur_node->taint_inst.end()) {
        cur_node->taint_inst[addr] = 1;
    } else {
        cur_node->taint_inst[addr]++;
    }
    */
    //cout << "end of function" << endl;
}

double smartln(double x)
{
    double n = 5;
	double alpha = (x-1)/(x+1), ans = alpha;
	double save = ans * alpha * alpha;

	for (int i = 2 ; i <= n ; i++)
	{
		ans += (1.0/(2*i-1)) * save;
		save = save * alpha * alpha;
	}

	return 2.0*ans;
}

double getlog(double x) {
    if (taint_weight == 0) return x;

    return smartln(x) / smartln(taint_weight);
}

void get_score(FuncNode *my_node) {
    double my_score;
    double callee_score;
    
    if (my_node == NULL) {
        return;
    }

    my_score = 0;
    callee_score = 0;

    // callee score
    for (auto iter = my_node->callee.begin(); iter != my_node->callee.end(); iter++) {
        get_score(*iter);
    }

    for (auto iter = my_node->callee.begin(); iter != my_node->callee.end(); iter++) {
        if ((*iter)->taint_inst_used == 1) {
            my_node->taint_inst_used = 1;
        }

        callee_score += callee_weight * ((*iter)->score);
    }



    // my score
    for (auto bbl_iter = my_node->taint_inst.begin(); bbl_iter != my_node->taint_inst.end(); bbl_iter++) {
        //cout << "score : " << iter->second << endl;
        auto inner_map = bbl_iter->second;
        for (auto ins_iter = inner_map.begin(); ins_iter != inner_map.end(); ins_iter++) {
            my_score += (getlog((double)(ins_iter->second)) * 100);
        }
        //my_score += (1 + smartln((double)(iter->second))) * 100;
    }
    my_node->my_score = my_score;

    my_node->score = my_score + callee_score;

    //printf("get score\n");
    if (taint_func.find(my_node->func_name) == taint_func.end()) {
        taint_func_ptr[my_node->func_name] = my_node;
        taint_func[my_node->func_name] = my_node->score;
        taint_seq[my_node->func_name] = my_node->seq_num;
        taint_depth[my_node->func_name] = my_node->depth;
    } else if (taint_seq[my_node->func_name] > my_node->seq_num) {
        taint_func_ptr[my_node->func_name] = my_node;
        taint_seq[my_node->func_name] = my_node->seq_num;
        taint_func[my_node->func_name] = my_node->score;
        taint_depth[my_node->func_name] = my_node->depth;
    } 
}

void get_score_list(FuncNode *my_node) {
    if ((my_node->func_name).compare(".plt.got") == 0) {}
    else if ((my_node->func_name).compare(".plt.sec") == 0) {}

    else {
        ScoreNode *score_node_temp = new ScoreNode;
        score_node_temp->func_name = my_node->func_name;
        score_node_temp->seq_num = my_node->seq_num;
        score_node_temp->my_score = my_node->my_score;
        score_node_temp->depth = my_node->depth;

        func_score_list.push_back(score_node_temp);
    }
    for (auto iter = my_node->callee.begin(); iter != my_node->callee.end(); iter++) {
        get_score_list(*iter);
    }
}

typedef struct ScoreRange {
    string entry_name;
    string exit_name;
    double score;
    int zero_func;
    int non_zero_func;
} ScoreRange;
vector<ScoreRange *> scores;

typedef struct EntryNode {
    string func_name;
    int depth;
    double score;
    int zero_func;
    int non_zero_func;
} EntryNode;

double score_pow(double score, int pow) {
    for (int i = 0; i < pow; i++) {
        score *= callee_weight;
    }
    return score;
}

void get_score_range() {
    vector<EntryNode *> entry_nodes;
    ScoreNode *current_node;
    for (auto iter1 = func_score_list.begin(); iter1 != func_score_list.end(); iter1++) {
        EntryNode *temp_entry;       
        current_node = *iter1;
        if (current_node->depth > 6) continue;

        for (auto iter2 = entry_nodes.begin(); iter2 != entry_nodes.end(); iter2++) {
            EntryNode *current_entry = *iter2;
            ScoreRange *temp_score;
            
            if (current_node->depth > current_entry->depth) continue;
            temp_score = new ScoreRange;
            temp_score->entry_name = current_entry->func_name;
            temp_score->exit_name = current_node->func_name;
            
            current_entry->score += score_pow(current_node->my_score, current_node->depth);
            if (current_node->my_score == 0) {
                current_entry->zero_func += 1;
            } else {
                current_entry->non_zero_func += 1;
            }
            temp_score->score = current_entry->score;
            temp_score->zero_func = current_entry->zero_func;        
            temp_score->non_zero_func = current_entry->non_zero_func;   
            scores.push_back(temp_score);
        }

        if (current_node->my_score == 0) continue;

        temp_entry = new EntryNode;
        temp_entry->func_name = current_node->func_name;
        temp_entry->depth = current_node->depth;
        temp_entry->score = score_pow(current_node->my_score, current_node->depth);
        temp_entry->zero_func = 0;
        temp_entry->non_zero_func = 0;
        if (temp_entry->score == 0) temp_entry->zero_func += 1;
        else temp_entry->non_zero_func += 1;
        entry_nodes.push_back(temp_entry);
    }
    // for (auto iter = scores.begin(); iter != scores.end(); iter++) {
    //     ScoreRange *cur_score_range = *iter;
    //     cur_score_range->score = cur_score_range->score / cur_score_range->zero_func;
    // }
}

void print_taint_info() {
    fstream new_file;
    fstream more_info;
    fstream eval_info;

    new_file.open("taint_list", ios::out);
    more_info.open("score_info", ios::out);
    
    char eval_file_name[100];
    sprintf(eval_file_name, "%g_%d", callee_weight, taint_weight);
    eval_info.open(eval_file_name, ios::out);

    if (!new_file) {
        cout << "file creation failed" << endl;
        return;
    }
    get_score(root_node);
    get_score_list(root_node);
    // for (auto iter = func_score_list.begin(); iter != func_score_list.end(); iter++) {
    //     ScoreNode *score_iter = *iter;
    //     // cout << "funcname : " << score_iter->func_name << ", score : " << score_iter->my_score << ", depth : " << score_iter->depth << endl;
    // }
    get_score_range();
    vector<pair<ScoreRange *, unsigned long>> score_range_sorted;
    for (auto iter = scores.begin(); iter != scores.end(); iter++) {
        ScoreRange *my_node = *iter;
        score_range_sorted.push_back(make_pair(my_node, my_node->score));
    }

    fstream score_range;
    score_range.open("score_range", ios::out);
    cout << "get score range" << endl;
    sort(score_range_sorted.begin(), score_range_sorted.end(), [] (const auto &x, const auto &y) {return x.second > y.second;});
    for (auto iter = score_range_sorted.begin(); iter != score_range_sorted.end(); iter++) {
        ScoreRange *cur_score_range = iter->first;
        double final_score = (cur_score_range->score) * ((double)cur_score_range->non_zero_func) / ((double)cur_score_range->zero_func);
        score_range << final_score << "," << cur_score_range->entry_name << "," << cur_score_range->exit_name << endl;
    }
    score_range.close();

    cout << endl << "======================test=====================" << endl;
    vector<pair<FuncNode *, unsigned long>> taint_node_sorted;
    for (auto iter = taint_func_ptr.begin(); iter != taint_func_ptr.end(); iter++) {
        FuncNode *my_node = iter->second;

        if (my_node->my_score < 1) {
            // continue;
        }
        if (my_node->seq_num < read_seq_num) {
            // before read systemcall 
            // continue;
        }
        if (my_node->taint_inst_used == 0) {
            continue;
        }

        taint_node_sorted.push_back(make_pair(my_node, my_node->score));
    }    

    eval_info << "callee_weight : " << callee_weight << ", taint_weight : " << taint_weight << endl;

    int i = 0;
    sort(taint_node_sorted.begin(), taint_node_sorted.end(), [] (const auto &x, const auto &y) {return x.second > y.second;});
    for (auto iter = taint_node_sorted.begin(); iter != taint_node_sorted.end(); iter++) {
        FuncNode *my_node = iter->first;
    
        // cout << "==========" << my_node->func_name << "==========" << endl;
        // cout << "Total Score : " << my_node->score << endl;
        // cout << "My Score : " << my_node->my_score << endl;
        // cout << "Total BBL : " << my_node->taint_inst.size() << endl;
        // cout << "Original Value Used : " << my_node->origianl_tag_used << endl;
        // cout << "Modified Value Used : " << my_node->modified_tag_used << endl;

        // cout << "Callee Score : " << my_node->score - my_node->my_score << endl;

        more_info << "==========" << my_node->func_name << "==========" << endl;
        more_info << "Total Score : " << my_node->score << endl;
        more_info << "My Score : " << my_node->my_score << endl;
        more_info << "Total BBL : " << my_node->taint_inst.size() << endl;
        more_info << "Original Value Used : " << my_node->origianl_tag_used << endl;
        more_info << "Modified Value Used : " << my_node->modified_tag_used << endl;

        more_info << "Callee Score : " << my_node->score - my_node->my_score << endl;

        new_file << my_node->func_name << ",";
        new_file << my_node->score << endl;

        i++;
        eval_info << i << ". " << my_node->func_name << ",";
        eval_info << my_node->score << endl;

        int tainted_callee = 0;
        for (auto callee_iter = my_node->callee.begin(); callee_iter != my_node->callee.end(); callee_iter++) {
            if ((*callee_iter)->score >= 1) {
                tainted_callee++;
            }
        }
        // cout << "Total Callee : " << my_node->callee.size() << endl;
        // cout << "Tainted Callee : " << tainted_callee << endl;

        // cout << "depth : " << my_node->depth << endl;

        more_info << "Total Callee : " << my_node->callee.size() << endl;
        more_info << "Tainted Callee : " << tainted_callee << endl;
        more_info << "callee_weight : " << callee_weight << ", taint_weight : " << taint_weight << endl;

        more_info << "depth : " << my_node->depth << endl;
    }    
    new_file.close();
    more_info.close();
    eval_info.close();
}

/* for debugging */
tag_t is_tainted(ADDRINT addr, size_t size) {
    tag_t cur_tag;
    for (size_t i = 0; i < size; i++) {
        cur_tag = tagmap_getb(addr+i);
        cout << "[" << hex << (addr+i) << "] : ";
        cout << "{" << dec << cur_tag << ", " << hex << ((uint32_t)(tagVal[cur_tag]) & 0xff) << "}" << endl;
    }
    
    return tagmap_getb(addr);
}

void print_tagged_memory(int pollute) {
    FILE *pFile = NULL;
	char map_buf[1024];
	char *map_ptr;

    cout << "print tagged memory : " << pollute << endl;
    pFile = fopen("/proc/self/maps", "r");

	while(fgets(map_buf, 1024, pFile)) {
		char *addr1;
		char *addr2;

		unsigned long min, max;
		int i;

		map_ptr = strtok(map_buf, " ");
		
		i = 0;
		while (1) {
			if (map_ptr[i] == '-') {
				map_ptr[i] = '\0';
				addr1 = map_ptr;
				addr2 = map_ptr+i+1;
				break;
			}
			i++;
		}
		min = strtol(addr1, NULL, 16);
		max = strtol(addr2, NULL, 16);

		map_ptr = strtok(NULL, " ");
		if (1) {
            unsigned long cur_addr = min;
            while (cur_addr < max) {
                tag_t cur_tag;
                if (pollute == 0 && (cur_tag = tagmap_getb(cur_addr)) != 0 && cur_tag < 10000000) {
                    cout << "[" << hex << cur_addr << "] : ";
                    cout << "{" << dec << cur_tag << ", " << hex << ((uint32_t)(tagVal[cur_tag]) & 0xff) << "}" << endl;
                } else if (pollute == 1 && (cur_tag = tagmap_getb(cur_addr)) != 0) {
                    cout << "[" << hex << cur_addr << "] : ";
                    cout << "{" << dec << (int)cur_tag << ", " << hex << ((uint32_t)(tagVal[cur_tag]) & 0xff) << "}" << endl;
                }
                cur_addr++;
            }
		} 
	}
	fclose(pFile);
}