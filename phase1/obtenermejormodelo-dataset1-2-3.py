import pandas as pd                                                                                    
import matplotlib.pyplot as plt                                                                        
import numpy as np
import io                                                                                                 
import itertools                                                                       
import matplotlib.pyplot as py                                       

from sklearn import model_selection

from sklearn.preprocessing import StandardScaler
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis

from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold
from sklearn.model_selection import train_test_split

from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.gaussian_process.kernels import RBF
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from sklearn.ensemble import VotingClassifier
from sklearn.externals import joblib 

dateparse = lambda x: pd.datetime.strptime(x, '%Y/%m/%d %H:%M:%S.%f') # 2018/07/22 13:01:34.892833

#Procesamiento básico del dataset
def process_file (dataset):

   # Clean the normal dataset by deleting the rows without Label (now only the management records from Argus)
   dataset = dataset.dropna(subset=['Label'], how='any', axis=0)

   # Replace the column Label for only 'Malware', 'Normal' or 'Background'
   dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*Botnet.*$)', 'Malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-WebServer.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-DNS-Server.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*MatLab-Server*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*To-DHCP-server*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*Background*$)', 'Background')

   

   # There is still one more label without normal, malware or backround. (an error), so delete it.
   dataset = dataset[~dataset.Label.str.contains("Established")]
   # Also delete all the rows that are labeled 'Background'
   dataset = dataset[~dataset.Label.str.contains("Background")]

   dataset = dataset.drop('CCDetector(Normal:CC:Unknown)', axis=1)  

   return dataset
##
#
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

print('Building a new dataset with dataset1, dataset2 y dataset3. A new mixed dataset')
interesting_files=['dataset1-capture20110818-binetflow.csv','dataset2-capture20110819.binetflow','dataset3-2018-05-03_win11.binetflow']

df_list = []
for filename in sorted(interesting_files):
    print (filename)
    df_list.append(pd.read_csv(filename, sep=',', parse_dates=['StartTime'] , date_parser=dateparse))
    df = pd.concat(df_list)

print ('Label count for each value in the original dataset')
test_dataset = process_file(df)

malware_count = 0
normal_count = 0

for t in test_dataset.itertuples():
    if t.Label=='Malware':
        malware_count += 1
    else:
        normal_count += 1

print('Total flows labeled as Malware in original dataset')
print(malware_count)
print('Total flows labeled as Normal in original dataset')
print(normal_count)

print('Processing Mixed Test Dataset. Real mixed on real-time')
test_dataset = process_features(test_dataset)

#también borré las columnas que tenian valores NA
test_dataset = test_dataset.dropna(how='any', axis=1)

y = test_dataset['Label']
X = test_dataset.drop('Label', axis=1)

X_train_mixed, X_test_mixed, y_train_mixed, y_test_mixed = train_test_split(X, y, train_size=0.75)
#esto lo hice para tener separado el dataset para correr el Predecir y obtener los resultados para la fase 2
#pero está mal porque ya está cortado :-(

##Analyse if the train and test set have the same proportion of malicious and normal labels as the original dataset

malware_in_train = 0
normal_in_train = 0
malware_in_test = 0
normal_in_test = 0

print ('Label count for each value in y_train_mixed')
#seguir desde acá
for elem in y_train_mixed:
    if elem=='Malware':
        malware_in_train += 1
    else:
        normal_in_train += 1
print('Flows labeled as malware in y_train_mixed')
print(malware_in_train)
print('Flows labeled as normal in y_train_mixed')
print(normal_in_train)

for elem in y_test_mixed:
    if elem=='Malware':
        malware_in_test += 1
    else:
        normal_in_test += 1
print ('Label count for each value in y_test_mixed')
print('Flows labeled as malware in y_test_mixed')
print(malware_in_test)
print('Flows labeled as normal in y_test_mixed')
print(normal_in_test)

##end of analysis

#sc = StandardScaler()
#sc.fit(X_train_mixed)
#X_train_mixed_std = sc.transform(X_train_mixed)


#prueba de algoritmos antes del ensembling
#prueba de algoritmos antes del ensembling

SEED=8
clf1 = LogisticRegression(random_state=SEED)
clf2 = RandomForestClassifier(random_state=SEED)
clf3 = GaussianNB()
clf4 = SVC()
clf5 = KNeighborsClassifier(n_neighbors=3)
clf6 = MLPClassifier((80, 10), early_stopping=False, random_state=SEED)
clf7 = DecisionTreeClassifier()

#Now ensembling
#eclf = VotingClassifier(estimators=[('lr', clf1), ('rf', clf2), ('gnb', clf3)], voting='soft')
#https://sebastianraschka.com/Articles/2014_ensemble_classifier.html

df = pd.DataFrame(columns=('w1', 'w2', 'w3', 'mean', 'std', 'scores'))

#para probar otros algoritmos que no sean LR cambiar 
print ('prueba de voting pesado con LR, RF y NB')
i = 0
for w1 in range(1,4):
    for w2 in range(1,4):
        for w3 in range(1,4):

            if len(set((w1,w2,w3))) == 1: # skip if all weights are equal
                continue
            #Train the ensemblingClassiffier
            eclf = VotingClassifier(estimators=[('lr', clf1), ('RF', clf2), ('gnb', clf3)], voting='soft',weights=[w1,w2,w3] )
            eclf.fit(X_train_mixed, y_train_mixed)
            joblib.dump(eclf, 'modelo_entrenado-'+str(w1)+'-'+str(w2)+'-'+str(w3)+'.pkl')
            scores = cross_val_score(eclf, X_test_mixed, y_test_mixed, cv=5, scoring='accuracy')
            df.loc[i] = [w1, w2, w3, scores.mean(), scores.std(), scores]
            i += 1


df.sort_values(['mean', 'std'], ascending=False)
print(df.head (30))




