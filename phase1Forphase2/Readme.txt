In this phase we use the ensembling technique know as voting with weight to label flows as malicious or normal. 
We use ensembling to obtain a decision based in the results of three classifiers: Logistic Regression, Random Forest and Gradient Boosting.
We use this techniques because in a previous work (scripts are in the Phase1 folder of this structure) 
we evaluate different ensembling techniques and this one has the better accuracy.

Scripts description:
1-obtainBetterModel-dataset1-2-3.py --> implements the same tests doing in Phase 1 with 3 datasets to corroborate the Phase 1 results
and creates the model
trainingandtesting-dataset1-2-3.py --> to predict labels for the data of the 3 datasets using the created model. As result we obtain 
 	resultsFase1-dataset1-2-3.csv (dataset to train and test phase 2 implementation)
trainingandtesting-dataseet1-2-3withRandom.py -->  to predict labels for the data of the 3 datasets using the created model. It includes
the insertion of errors in some random rows (10%), to simulate errors in phase 1 decision. As result we obtain resultsFase1conrandom-dataset1-2-3.csv 
(dataset to train and test phase 2 implementation)
