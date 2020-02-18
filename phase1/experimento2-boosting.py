import pandas as pd                                                                                    
import matplotlib.pyplot as plt                                                                        
import numpy as np
import io                                                                                                 
import itertools                                                                       
import matplotlib.pyplot as py                                       

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis
from sklearn import model_selection
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold

from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.gaussian_process.kernels import RBF
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from sklearn.ensemble import AdaBoostClassifier

dateparse = lambda x: pd.datetime.strptime(x, '%Y/%m/%d %H:%M:%S.%f') # 2018/07/22 13:01:34.892833

#Procesamiento básico del archivo
def process_file (filename):

   archivo=open(filename) 
   
   dataset = pd.read_csv(archivo, sep=',', parse_dates=['StartTime'] , date_parser=dateparse)

   # Clean the normal dataset by deleting the rows without Label (now only the management records from Argus)
   dataset = dataset.dropna(subset=['Label'], how='any', axis=0)

   # Replace the column Label for only 'Malware', 'Normal' or 'Background'
   dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*Botnet.*$)', 'Malware')

   # There is still one more label without normal, malware or backround. (an error), so delete it.
   dataset = dataset[~dataset.Label.str.contains("Established")]
   # Also delete all the rows that are labeled 'Background'
   dataset = dataset[~dataset.Label.str.contains("Background")]

   dataset = dataset.drop('CCDetector(Normal:CC:Unknown)', axis=1)  

   return dataset
##

# This function is used to convert string features into categories for pandas
# A categorical variable takes on a limited, and usually fixed, number of possible values
# In this way, the algorihtms can do something with the features. If not, they can not use them
def make_categorical(dataset, cat):
    '''
    Convert one column to a categorical type
    '''
    # Converts the column to cotegorical
    dataset[cat] = pd.Categorical(dataset[cat])
    # Convert the categories to int. Use this with caution!! we don't want an algorithm 
    # to learn that an Orange=1 is less than a pearl=2
    dataset[cat] = dataset[cat].cat.codes
    return dataset

# This function discards some features and convert others.
# In here you can later modify how you use the features in the flows
# Maybe you want to delete some features, or convert others.
# For example our port feature is not a number now (because of the ICMP codes), but you can change that

# Por ahi no es una mala idea más allá de descartar la IP conservar la información de la red..

def process_features(dataset):
    '''
    Discards some features of the dataset and can create new.
    '''
    try:
      print('\tDiscarding column {}'.format('StartTime'))
      dataset = dataset.drop('StartTime', axis=1)
    except ValueError:
      pass
    dataset.reset_index()
    try:
      print('\tDiscarding column {}'.format('SrcAddr'))
      dataset = dataset.drop('SrcAddr', axis=1)
    except ValueError:
      pass
    try:
      print('\tDiscarding column {}'.format('DstAddr'))
      dataset = dataset.drop('DstAddr', axis=1)
    except ValueError:
      pass
    try:
      print('\tDiscarding column {}'.format('sTos'))
      dataset = dataset.drop('sTos', axis=1)
    except ValueError:
      pass
    try:
      print('\tDiscarding column {}'.format('dTos'))
      dataset = dataset.drop('dTos', axis=1)
    except ValueError:
      pass
    # Create categorical features
    try:
      print('\tMake categorical column {}'.format('Dir'))
      dataset = make_categorical(dataset, 'Dir')
    except ValueError:
      pass
    try:
      print('\tMake categorical column {}'.format('Proto'))
      dataset = make_categorical(dataset, 'Proto')
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      print('\tMake categorical column {}'.format('Sport'))
      dataset = make_categorical(dataset, 'Sport')
    except ValueError:
      pass
    try:
      print('\tMake categorical column {}'.format('State'))
      dataset = make_categorical(dataset, 'State')
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      print('\tMake categorical column {}'.format('Dport'))
      dataset = make_categorical(dataset, 'Dport')
    except ValueError:
      pass
    return dataset

def makecategorical_features(dataset):
   # Create categorical features
    try:
      print('\tMake categorical column {}'.format('Dir'))
      dataset = make_categorical(dataset, 'Dir')
    except ValueError:
      pass
    try:
      print('\tMake categorical column {}'.format('Proto'))
      dataset = make_categorical(dataset, 'Proto')
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      print('\tMake categorical column {}'.format('Sport'))
      dataset = make_categorical(dataset, 'Sport')
    except ValueError:
      pass
    try:
      print('\tMake categorical column {}'.format('State'))
      dataset = make_categorical(dataset, 'State')
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      print('\tMake categorical column {}'.format('Dport'))
      dataset = make_categorical(dataset, 'Dport')
    except ValueError:
      pass
    return dataset

print('Basic Processing Mixed Test Dataset. Real mixed on real-time')
nombrearchivo='capture20110818-binetflow.csv'
test_dataset= process_file(nombrearchivo)

print('Processing Mixed Test Dataset. Real mixed on real-time')
test_dataset = process_features(test_dataset)

#también borré las columnas que tenian valores NA
test_dataset = test_dataset.dropna(how='any', axis=1)

#para probar los algoritmos
y_test_mixed = test_dataset['Label']
X_test_mixed = test_dataset.drop('Label', axis=1)

sc = StandardScaler()
sc.fit(X_test_mixed)
X_test_mixed_std = sc.transform(X_test_mixed)


#prueba de algoritmos antes del ensembling

SEED=8
clf1 = LogisticRegression(random_state=SEED)
clf2 = RandomForestClassifier(random_state=SEED)
clf3 = GaussianNB()
clf4 = SVC ()
clf5 = KNeighborsClassifier(n_neighbors=3)
clf6 = DecisionTreeClassifier()

#print('5-fold cross validation:\n')
#print ('pruebas sin ensembling:\n')
#labels = ['Logistic Regression', 'Random Forest', 'Naive Bayes', 'SVC', 'KNeighbords', 'DT']

#for clf, label in zip([clf1, clf2, clf3, clf4], labels):

#    scores = model_selection.cross_val_score(clf, X_test_mixed_std, y_test_mixed, cv=5, scoring='accuracy')
#    print("Accuracy: %0.10f (+/- %0.10f) [%s]" % (scores.mean(), scores.std(), label))

num_trees = 50
#Ahora ensembling boosting con LR
#label='Adaboost con LR'
#model = AdaBoostClassifier(n_estimators=num_trees, base_estimator=clf1, random_state=SEED)
#results = model_selection.cross_val_score(model, X_test_mixed_std, y_test_mixed, cv=5)
#print("Accuracy: %0.10f (+/- %0.10f) [%s]" % (results.mean(), results.std(), label))

#Ahora ensembling boosting con RF 
#label='Adaboost con RF' 
#model = AdaBoostClassifier(n_estimators=num_trees, base_estimator=clf2, random_state=SEED)
#results = model_selection.cross_val_score(model, X_test_mixed_std, y_test_mixed, cv=5)
#print("Accuracy: %0.10f (+/- %0.10f) [%s]" % (results.mean(), results.std(), label))

#Ahora ensembling boosting con GaussianNB 
#label='Adaboost con GaussianNB' 
#model = AdaBoostClassifier(n_estimators=num_trees, base_estimator=clf3, random_state=SEED)
#results = model_selection.cross_val_score(model, X_test_mixed_std, y_test_mixed, cv=5)
#print("Accuracy: %0.10f (+/- %0.10f) [%s]" % (results.mean(), results.std(), label))

#Ahora ensembling boosting con SVC 
#label='Adaboost con SVC' 
#model = AdaBoostClassifier(n_estimators=num_trees, base_estimator=clf4, random_state=SEED)
#results = model_selection.cross_val_score(model, X_test_mixed_std, y_test_mixed, cv=5)
#print("Accuracy: %0.10f (+/- %0.10f) [%s]" % (results.mean(), results.std(), label))

#Ahora ensembling boosting con DT 
label='Adaboost con DT' 
model = AdaBoostClassifier(n_estimators=num_trees, base_estimator=clf6, random_state=SEED)
results = model_selection.cross_val_score(model, X_test_mixed_std, y_test_mixed, cv=5)
print("Accuracy: %0.10f (+/- %0.10f) [%s]" % (results.mean(), results.std(), label))

