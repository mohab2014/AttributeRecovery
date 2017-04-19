
/* 
 * File:   attributeRecovery.cpp
 * Author: (work under conference submission about a paper entitled ``Inference Attacks on Searchable Encrypted Relational Databases")
 *
 * Created on March 14, 2017, 5:24 PM
 
 
 The co-occurrence matrix has been computed and saved in a file called observed287.txt. Our program is able to divide most
 of the queries into classes where each class belongs to a single attribute name. However, regarding attributes sharing the
 same cardinality such as sex/salary_class with cardinality 2, our program puts the queries belonging into the same attribute 
 into the same class. Such an approach fails to do the separation for the attributes education/education-num because they 
 co-exist together in evevery record. That means for every education value, there is always a corresponding eudcation-num value. 
 Clearly such a scenario will not exist in most relational databases and even if it does, it won't be interesting for an attacker. 
 However, the education/education-num scenario serves as a good example to show when our attack algorithm can fail.
 
 It takes less than 3 minutes to recover all the discrete attributes. Those with unique cardinality are recovered with probability
 1. sex/salary_class values are separated with probability 1 but we cannot tell which set refers to sex and which refers to salary_class
 since both have same cardinality 2. 
 
 */

#include <cstdlib>


#include <cstdio>

#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <algorithm>
#include <ctime>

#define maxNoQueries 287
#define maxNoAttributes 12
#define MaxNoAttempts 5

#define MAX 33000

using namespace std;

int target_cardinality = 2;
int Ct[maxNoQueries+1][maxNoQueries+1] = {{0}};
int no_solutions = 0;

bool** dp;


class Attribute
{
public:
    string name;
    int cardinality;
    int attempts_to_resolve;
};

class Query
{
public:
    int query_no;
    int result_size;
    vector<Query> *queryList;
};

bool operator< (Query qi,Query qj) { int xi,xj; if(qi.queryList == NULL) xi = 0; else xi = qi.queryList->size(); if(qj.queryList==NULL) xj=0; else xj = qj.queryList->size(); return xi<xj;}
 
std::ostream& operator<<(std::ostream& out, const Query& q){ if(q.queryList == NULL) out<<"(0,"<<q.query_no<<","<<q.result_size<<")"; else out<<"("<<q.queryList->size()<<","<<q.query_no<<","<<q.result_size<<")";}

bool operator== (Query qi,Query qj) { return (qi.query_no==qj.query_no) && (qi.result_size == qj.result_size);}

bool isQueryRemoved(Query q){return (q.query_no == -1);}
bool isEqual(Query qi,Query qj) { return (qi.query_no==qj.query_no && qi.result_size == qj.result_size);}


vector<Query> correctSolutions[MAX];


//-------------------------------------------------------------------------------

bool testZeroCo_Occurrence(const vector<Query>& v)
{
        for(int i = 0;i < v.size();i++)
        {
            for(int j = i+1;j < v.size();j++)
            {
                if(Ct[v[i].query_no][v[j].query_no] != 0)
                {
                    return false;
                }
            }
        }
        
        
        return true;
}


//-------------------------------------------------------------------------------


void saveCorrectSolution(const vector<Query>& v) {

       
    if(v.size() == target_cardinality)
    {
        
        //if(testZeroCo_Occurrence(v)==true)
        //{
          
          no_solutions++;
          
          correctSolutions[no_solutions] = v; 
          
        //}
        
        
    }
}

void display(const vector<Query>& v)
{ 
      for (int i = 0; i < v.size(); ++i)
             cout<<v[i].query_no<<":"<<v[i].result_size<<";";
      cout<<endl;
          
}
//-----------------------------------------------------------------------------------------

void output(const vector<Query>& queryList, int i, int sum, vector<Query>& p) {
    
    if (i == 0 && sum != 0 && dp[0][sum]) {
        p.push_back(queryList[i]);
          
        if(testZeroCo_Occurrence(p)==true){
            
           saveCorrectSolution(p);
        }
        return;
    }
    if (i == 0 && sum == 0) {
        saveCorrectSolution(p);
        return;
    }
    if (dp[i - 1][sum]) {
        vector<Query> b = p;
        output(queryList, i - 1, sum, b);
    }
    if (sum >= queryList[i].result_size && dp[i - 1][sum - queryList[i].result_size]) {
        p.push_back(queryList[i]);
        
        if(testZeroCo_Occurrence(p)==true)
            output(queryList, i - 1, sum - queryList[i].result_size, p);
    }
}


//---------------------------------------------------------------------------------------------------
bool subsetSum(vector<Query>& queryList, int sum) {
  
    if (queryList.size() == 0 || sum < 0) 
        return false;
    if(dp != NULL)
    {
        delete dp;
        dp = NULL;
    }
    dp = new bool*[queryList.size()];
    for (int i = 0; i < queryList.size(); ++i) {
        dp[i] = new bool[sum + 1];
        dp[i][0] = true;
    }
    for (int i = 1; i < sum + 1; ++i)
        dp[0][i] = (queryList[0].result_size == i) ? true : false;
    for (int i = 1; i < queryList.size(); ++i)
        for (int j = 0; j < sum + 1; ++j)
            dp[i][j] = (queryList[i].result_size <= j) ? dp[i - 1][j] || dp[i - 1][j - queryList[i].result_size] : dp[i - 1][j];
    
    if (!dp[queryList.size() - 1][sum]) {
        return false;
    }
    
    return true;
    
    
}



//-------------------------------------------------------------



/*
 * 
 */
int main(int argc, char** argv) 
{ 


    
    std::ifstream infile("observed287.txt");

    int x, y, f; //read the three integers, queries number x and y and their joint frequency value f 
    char c1, c2; //read two commas


    for(int i = 0;i < maxNoQueries+1;i++)
        for(int j = 0;j < maxNoQueries+1;j++)
            Ct[i][j] = 0;
                 
    
    while (infile >> x >> c1 >> y >> c2 >> f)
    {

      Ct[x][y] = f;
      Ct[y][x] = f;
      
      //cout<<"Ct["<<x<<"]["<<y<<"] = "<<Ct[x][y]<<";"<<endl;
    }

   
    int number_of_records = 32561;
    
    
    
    
    //for each query q_i, attach all other queries q_j satisfying Ct[q_i][q_j] = 0
    
    
    vector<int> queriesSize;
    vector<Query> queries;
    
    queriesSize.push_back(0);//query number 0 means non-existant query
    
    Query dummy;
    dummy.query_no = 0;
    dummy.result_size = 0;
    dummy.queryList = NULL;
    queries.push_back(dummy);
    
    for(int i = 1;i < maxNoQueries+1;i++)
    {
        
        
        Query qi;
        
        qi.query_no = i;
        qi.result_size = Ct[i][i];
        
        qi.queryList = new vector<Query>();
        
        qi.queryList->push_back(qi);
        
        for(int j = 1;j < maxNoQueries+1;j++)
        {
            
            if(Ct[i][j] == 0)
            {
               Query qj;
               qj.query_no = j;
               qj.result_size = Ct[j][j];
               qj.queryList = NULL;
               qi.queryList->push_back(qj);  
            }
        
        }
            
        queriesSize.push_back(qi.queryList->size());
        
        queries.push_back(qi);
        
        
    }
    
    
    
    //sort the queries according to their result sizes
    
 
    
    std::sort (queries.begin(), queries.end());
    
    
    // print out content:
    std::cout << "Queries vector contains:";
    for (int i = 0;i < maxNoQueries+1;i++)
      std::cout << ' ' << queries[i];
    std::cout << '\n';
    
    
    
    vector<Attribute> targetAttributes;
    
    Attribute attributeObj;
    
    attributeObj.name = "sex/salary_class";
    attributeObj.cardinality = 2;
    attributeObj.attempts_to_resolve = MaxNoAttempts;
    
    targetAttributes.push_back(attributeObj);
    
    
    attributeObj.name = "race";
    attributeObj.cardinality = 5;
    
    attributeObj.attempts_to_resolve = MaxNoAttempts;
    
    targetAttributes.push_back(attributeObj);
    
    attributeObj.name = "relationship";
    attributeObj.cardinality = 6;
    
    attributeObj.attempts_to_resolve = MaxNoAttempts;
    
    targetAttributes.push_back(attributeObj);
    
    
    attributeObj.name = "marital_status";
    attributeObj.cardinality = 7;
    
    attributeObj.attempts_to_resolve = MaxNoAttempts;
    
    targetAttributes.push_back(attributeObj);
    
    
    attributeObj.name = "workclass";
    attributeObj.cardinality = 9;
    
    attributeObj.attempts_to_resolve = MaxNoAttempts;
    
    targetAttributes.push_back(attributeObj);
    
    
    attributeObj.name = "occupation";
    attributeObj.cardinality = 15;
    
    attributeObj.attempts_to_resolve = MaxNoAttempts+10;
    
    targetAttributes.push_back(attributeObj);
    
    
    
    attributeObj.name = "education/education-num";
    attributeObj.cardinality = 16;
    
    attributeObj.attempts_to_resolve = MaxNoAttempts+5;
    targetAttributes.push_back(attributeObj);
    
    
    
    
    attributeObj.name = "native-country";
    attributeObj.cardinality = 42;
    
    attributeObj.attempts_to_resolve = MaxNoAttempts+5;
    targetAttributes.push_back(attributeObj);
    
    
    attributeObj.name = "hours-per-week/age";
    attributeObj.cardinality = 75; //continuous but we can consider 140 as an extreme upperbound
    
    attributeObj.attempts_to_resolve = MaxNoAttempts+20;
    //targetAttributes.push_back(attributeObj);
    
    int total_no_of_solutions = 0;
    
    
    
    
    
    
    
    //queries is L in Algorithm 1
    cout<<"Choose the attribute with smallest cardinality as the target attribute from the list below."<<endl;
    
    for(int i = 0;i < targetAttributes.size();i++)
        cout<<i+1<<":"<<targetAttributes[i].name<<","<<targetAttributes[i].cardinality<<endl;
    
    
    int ctr = 0;
    
    int attempts = 0;
    
    
    clock_t begin = clock();
    
    while(targetAttributes.size() >= 1){
        
    
      target_cardinality = targetAttributes[0].cardinality; //assumption: 0 position has the min. card.
    
    
      ctr = 0;
      
            
      while(ctr <= maxNoQueries)
      {
          
          
          vector<Query> currentQueryList;
          do
          {
            ctr++;
            if(queries[ctr].queryList != NULL) 
            {    
                 if(queries[ctr].queryList->size()>=target_cardinality)
                 {
                    for(int j = 0;j < queries[ctr].queryList->size();j++)
                       currentQueryList.push_back(queries[ctr].queryList->at(j));
                   cout<<"current ctr = "<<ctr<<", size = "<<queries[ctr].queryList->size()<<endl;
                   break;
                 }
            }
                
            
            
          }while(true);
          
          for(int s = 0;s < currentQueryList.size();s++)
             cout<<currentQueryList[s]<<"\t";//currentQueryListResultSizes.push_back(currentQueryList[s].result_size);
          cout<<endl;
    
          cout<<"Resolving queries with a common attribute name equal to "<<targetAttributes[0].name<<" and with cardinality is "<<target_cardinality<<endl;

          int target_sum = number_of_records-currentQueryList[0].result_size;
          
          if(subsetSum(currentQueryList , target_sum ))
          {
              
             
             vector<Query> p;
    
             p.push_back(currentQueryList[0]); //let each solution include the first element in queryList since sum = number_of_records-queryList[0].resultsize
    
    
             output(currentQueryList, currentQueryList.size() - 1, target_sum, p);
              
             cout<<"current no of solutions = "<<no_solutions<<endl;
    
             attempts++;
      
      
             if(no_solutions == 1)
             {
             
               vector<Query> sol = correctSolutions[1];
          
               cout<<"One solution exists at ctr = "<<ctr<<" of size = "<<sol.size()<<endl;  
               display(sol);
             
          
               
               total_no_of_solutions += no_solutions;
               no_solutions = 0;
           
          
                
             }
             else if(no_solutions > 1)
             {
       
                attempts++;
                cout<<no_solutions <<" possible solutions exist at ctr = "<<ctr<<". We display (only) two of them. So our attack cannot decide which is the correct one and we leave it to be decided when the attacker gains background knowledge. We increment ctr and try next query list in order to see other possible solutions.\n";
          
                vector<Query> sol;
          
               //display only 2 solutions
               for(int i = 1; i <= 2;i++)
               {
                  sol = correctSolutions[i];
          
          
                 display(sol);
               }
          
          
               total_no_of_solutions += no_solutions;
          
               no_solutions = 0;
               
             }
            
           
           
                
      
          
      }        
      else 
          cout<<"There are no subsets with sum "<<number_of_records<<" in the current list whose head is "<<currentQueryList[0]<<". Try next list."<<endl;
             
 
             
             
      
      
      if(attempts == targetAttributes[0].attempts_to_resolve) 
      {
         cout<<attempts<<" different lists out of 287 lists have been examined in order to resolve a set of queries whose card. is "<<targetAttributes[0].cardinality<<". Next we look for another set of queries whose card. is "<<targetAttributes[1].cardinality<<endl;
         cout<<"Total number of solutions found = "<<total_no_of_solutions<<". Note that solutions found in different attempts might be similar (i.e. just another solution where the order of elements is different)."<<endl;
         cout<<"///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////"<<endl;
         targetAttributes.erase(targetAttributes.begin());
         total_no_of_solutions = 0;
         
         no_solutions = 0;
         
         attempts = 0;
         break;  
      }
      
    }
    
    
    
   }
    
   
    
    
  clock_t end = clock();
  double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
   
   
    
  cout<<"Total time in mins = "<< elapsed_secs/60 <<endl;
    
  
  if(dp != NULL)
  {
        delete dp;
        dp = NULL;
  }
    
    
    
    
  return 0;

}

