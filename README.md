# AttributeRecovery Attack


#Dataset: 

The Adult dataset has been encrypted using a searchable symmetric encryption scheme. 


#Program: 
The co-occurrence matrix has been computed and saved in a file called observed287.txt. Our program is able to divide most of the queries into classes where each class belongs to a single attribute name. However, regarding attributes sharing the same cardinality such as sex/salary-class with cardinality 2, our program puts the queries belonging into the same attribute into the same class. Such an approach fails to do the separation for the attributes  education/education-num because they co-exist together in evevery record. That means for every education value, there is always a corresponding eudcation-num value. Clearly such a scenario will not exist in most relational databases and even if it does, it won't be interesting for an attacker. However, the education/education-num scenario serves as a good example to show when our attack algorithm can fail.
 
