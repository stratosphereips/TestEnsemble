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

from sklearn.ensemble import VotingClassifier

dateparse = lambda x: pd.datetime.strptime(x, '%Y/%m/%d %H:%M:%S.%f') # 2018/07/22 13:01:34.892833

#Procesamiento básico del archivo
def process_file (filename):

   archivo=open(filename) 
   
   dataset = pd.read_csv(archivo, sep=',', parse_dates=['StartTime'] , date_parser=dateparse)

   # Clean the normal dataset by deleting the rows without Label (now only the management records from Argus)
   dataset = dataset.dropna(subset=['Label'], how='any', axis=0)

    # Replace the column Label for only 'Malware', 'Normal' or 'Background'
   #dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*Botnet.*$)', 'Malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*To-Background-CVUT-Proxy.*$)', 'malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Background.*$)', 'Unknow')
   
   # There is still one more label without normal, malware or backround. (an error), so delete it.
   #dataset = dataset[~dataset.Label.str.contains("Established")]
   # Also delete all the rows that are labeled 'Unknow'
   #The definitive ensembling will not receive labeled flows as Unknoe
   dataset = dataset[~dataset.Label.str.contains("Unknow")]
   
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
      # Create categorical features
    '''
    try:
      print('\tMake categorical column {}'.format('StartTime'))
      dataset = make_categorical(dataset, 'StartTime')
    except ValueError:
      pass
#    dataset.reset_index()
#    try:
#     print('\tMake categorical column {}'.format('SrcAddr'))
#      dataset = make_categorical(dataset, 'SrcAddr')
#    except ValueError:
#      pass
#    try:
#      print('\tMake categorical column {}'.format('DstAddr'))
#      dataset = make_categorical(dataset, 'DstAddr')
#    except ValueError:
#      pass
    try:
      print('\tMake categorical column {}'.format('sTos'))
      dataset = make_categorical(dataset, 'sTos')
    except ValueError:
      pass
    try:
      print('\tDiscarding column {}'.format('dTos'))
      dataset = dataset.drop('dTos', axis=1)
    except ValueError:
      pass
    try:
      print('\tDiscarding column {}'.format('Dir'))
      dataset = dataset.drop('Dir', axis=1)
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

def getStateFromFlags(state, pkts):
        """ 
        Analyze the flags given and return a summary of the state. Should work with Argus and Bro flags
        We receive the pakets to distinguish some Reset connections
        """
        try:
            #self.outputqueue.put('06|database|[DB]: State received {}'.format(state))
            pre = state.split('_')[0]
            try:
                # Try suricata states
                """
                 There are different states in which a flow can be. 
                 Suricata distinguishes three flow-states for TCP and two for UDP. For TCP, 
                 these are: New, Established and Closed,for UDP only new and established.
                 For each of these states Suricata can employ different timeouts. 
                 """
                if 'new' in state or 'established' in state:
                    return 'Established'
                elif 'closed' in state:
                    return 'NotEstablished'

                # We have varius type of states depending on the type of flow.
                # For Zeek 
                if 'S0' in state or 'REJ' in state or 'RSTOS0' in state or 'RSTRH' in state or 'SH' in state or 'SHR' in state:
                    return 'NotEstablished'
                elif 'S1' in state or 'SF' in state or 'S2' in state or 'S3' in state or 'RSTO' in state or 'RSTP' in state or 'OTH' in state: 
                    return 'Established'

                # For Argus
                suf = state.split('_')[1]
                if 'S' in pre and 'A' in pre and 'S' in suf and 'A' in suf:
                    """
                    Examples:
                    SA_SA
                    SR_SA
                    FSRA_SA
                    SPA_SPA
                    SRA_SPA
                    FSA_FSA
                    FSA_FSPA
                    SAEC_SPA
                    SRPA_SPA
                    FSPA_SPA
                    FSRPA_SPA
                    FSPA_FSPA
                    FSRA_FSPA
                    SRAEC_SPA
                    FSPA_FSRPA
                    FSAEC_FSPA
                    FSRPA_FSPA
                    SRPAEC_SPA
                    FSPAEC_FSPA
                    SRPAEC_FSRPA
                    """
                    return 'Established'
                elif 'PA' in pre and 'PA' in suf:
                    # Tipical flow that was reported in the middle
                    """
                    Examples:
                    PA_PA
                    FPA_FPA
                    """
                    return 'Established'
                elif 'ECO' in pre:
                    return 'ICMP Echo'
                elif 'ECR' in pre:
                    return 'ICMP Reply'
                elif 'URH' in pre:
                    return 'ICMP Host Unreachable'
                elif 'URP' in pre:
                    return 'ICMP Port Unreachable'
                else:
                    """
                    Examples:
                    S_RA
                    S_R
                    A_R
                    S_SA 
                    SR_SA
                    FA_FA
                    SR_RA
                    SEC_RA
                    """
                    return 'NotEstablished'
            except IndexError:
                # suf does not exist, which means that this is some ICMP or no response was sent for UDP or TCP
                if 'ECO' in pre:
                    # ICMP
                    return 'Established'
                elif 'UNK' in pre:
                    # ICMP6 unknown upper layer
                    return 'Established'
                elif 'CON' in pre:
                    # UDP
                    return 'Established'
                elif 'INT' in pre:
                    # UDP trying to connect, NOT preciselly not established but also NOT 'Established'. So we considered not established because there
                    # is no confirmation of what happened.
                    return 'NotEstablished'
                elif 'EST' in pre:
                    # TCP
                    return 'Established'
                elif 'RST' in pre:
                    # TCP. When -z B is not used in argus, states are single words. Most connections are reseted when finished and therefore are established
                    # It can happen that is reseted being not established, but we can't tell without -z b.
                    # So we use as heuristic the amount of packets. If <=3, then is not established because the OS retries 3 times.
                    if int(pkts) <= 3:
                        return 'NotEstablished'
                    else:
                        return 'Established'
                elif 'FIN' in pre:
                    # TCP. When -z B is not used in argus, states are single words. Most connections are finished with FIN when finished and therefore are established
                    # It can happen that is finished being not established, but we can't tell without -z b.
                    # So we use as heuristic the amount of packets. If <=3, then is not established because the OS retries 3 times.
                    if int(pkts) <= 3:
                        return 'NotEstablished'
                    else:
                        return 'Established'
                else:
                    """
                    Examples:
                    S_
                    FA_
                    PA_
                    FSA_
                    SEC_
                    SRPA_
                    """
                    return 'NotEstablished'
            #self.outputqueue.put('01|database|[DB] Funcion getFinalStateFromFlags() We didnt catch the state. We should never be here')
            #return None modificado por un valor concreto!
            return None
            return 'Indefinido' 
        except Exception as inst:
            #self.outputqueue.put('01|database|[DB] Error in getFinalStateFromFlags() in database.py')
            #self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            #self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))
            #self.print(traceback.format_exc())
            #las escrituras en la base de datos fueron reemplazadas por un valor concreto 
            return 'Indefinido' 



print('Basic Processing Mixed Test Dataset. Real mixed on real-time')
#nombrearchivo='prueba'
nombrearchivo='capture20110818-binetflow.csv'

df= process_file(nombrearchivo)

d = {}
d2 = {}
for t in df.itertuples():
    if t.SrcAddr not in d.keys():
        d[t.SrcAddr] = {'total1': 0, 'normal': 0, 'malware': 0 }
    if t.DstAddr not in d[t.SrcAddr].keys():
        d[t.SrcAddr][t.DstAddr] = {'total2': 0, 'normal': 0, 'malware': 0 }
        d2[t.SrcAddr+"-"+t.DstAddr] = {'SrcAddr': t.SrcAddr, 'DstAddr': t.DstAddr, 'TCPEstablishedPercentage': 0, 'TCPNotEstablishedPercentage': 0, 'UDPEstablishedPercentage': 0, 'UDPNotEstablishedPercentage': 0,'cantTCPE': 0,'cantTCPNE': 0, 'cantUDPE': 0, 'cantUDPNE': 0, 'originalLabel': ''}
    if t.Proto not in d[t.SrcAddr][t.DstAddr].keys():
        d[t.SrcAddr][t.DstAddr][t.Proto] = {'total3': 0, 'normal': 0, 'malware': 0 }
    state=getStateFromFlags(t.State,t.TotPkts)
    print(state)
    if state not in d[t.SrcAddr][t.DstAddr][t.Proto].keys():
        d[t.SrcAddr][t.DstAddr][t.Proto][state] = {'total4': 0, 'normal': 0, 'malware': 0 }
    d[t.SrcAddr]['total1'] += 1
    d[t.SrcAddr][t.DstAddr]['total2'] += 1
    d[t.SrcAddr][t.DstAddr][t.Proto]['total3'] += 1
    d[t.SrcAddr][t.DstAddr][t.Proto][state]['total4'] += 1
    if t.Label == 'Normal':
        d[t.SrcAddr]['normal'] += 1
        d[t.SrcAddr][t.DstAddr]['normal'] += 1
        d[t.SrcAddr][t.DstAddr][t.Proto]['normal'] += 1
        d[t.SrcAddr][t.DstAddr][t.Proto][state]['normal'] += 1
    else:
        d[t.SrcAddr]['malware'] += 1
        d[t.SrcAddr][t.DstAddr]['malware'] += 1
        d[t.SrcAddr][t.DstAddr][t.Proto]['malware'] += 1
        d[t.SrcAddr][t.DstAddr][t.Proto][state]['malware'] += 1

# compute some statistics...
def get_stats(src, dst, proto, state):
    pmalware_src = d[src]['malware']/d[src]['total1']
    pmalware_src_dst = d[src][dst]['malware']/d[src][dst]['total2']
    pmalware_src_dst_proto = d[src][dst][proto]['malware']/d[src][dst][proto]['total3']
    pmalware_src_dst_proto_state = d[src][dst][proto][state]['malware']/d[src][dst][proto][state]['total4']
    # como son conjuntos disjuntos, la prob de malware deberia ser igual a
    #    1 - pnormal
    return pmalware_src, pmalware_src_dst, pmalware_src_dst_proto, pmalware_src_dst_proto_state

infectadas=set(['147.32.84.165','147.32.84.191','147.32.84.192','147.32.84.193','147.32.84.204','147.32.84.205','147.32.84.206','147.32.84.207','147.32.84.208','147.32.84.209'])
limpias=set(['147.32.84.170','147.32.84.134','147.32.84.164','147.32.87.36','147.32.80.9','147.32.87.11'])

countInfected=0
FN=0
FP=0
TP=0
TN=0

df2 = pd.DataFrame([key for key in d2.keys()], columns=['ClaveSrcIPDstIP'])
for src in list(set(df.SrcAddr)):
    for dst in list(set(df[df.SrcAddr == src].DstAddr)):
        for proto in list(set(df[(df.SrcAddr == src) & (df.DstAddr == dst)].Proto)):
            for state_orig in list(set(df[(df.SrcAddr == src) & (df.DstAddr == dst) & (df.Proto == proto)].State)):
                pkts=df[(df.SrcAddr == src) & (df.DstAddr == dst) & (df.Proto == proto) & (df.State == state_orig)].TotPkts
                state=getStateFromFlags(state_orig,pkts)
                psrc,pdst,pproto,pstate = get_stats(src, dst, proto, state)
                key=src+"-"+dst
                print('(## %20s %20s %10s %10s ##)'%(src, dst, proto, state))
                print('Probabilidad de fuente infectada: %0.2f'%(psrc))
                print('Probabilidad de fuente y destino infectada: %0.2f'%(pdst))
                print('Probabilidad de fuente y destino y protocolo infectada: %0.2f'%(pproto))
                print('Probabilidad de fuente y destino y protocolo y estado infectada: %0.2f'%(pstate))

                if(proto=='tcp'):
                   if (state=='Established'):
                       d2[key]['TCPEstablishedPercentage']=pstate
                       d2[key]['cantTCPE']=d[src][dst][proto][state]['total4']
                   else:
                       if (state=='NotEstablished'):
                           d2[key]['TCPNotEstablishedPercentage']=pstate
                           d2[key]['cantTCPNE']=d[src][dst][proto][state]['total4']
                else:
                   if(proto=='udp'):
                       if (state=='Established'):
                           d2[key]['UDPEstablishedPercentage']=pstate
                           d2[key]['cantUDPE']=d[src][dst][proto][state]['total4']
                       else:
                           if (state=='NotEstablished'):
                               d2[key]['UDPNotEstablishedPercentage']=pstate
                               d2[key]['cantUDPNE']=d[src][dst][proto][state]['total4']
                if(src in infectadas):
                    d2[key]['originalLabel']='Infectada'
                else:
                    if(src in limpias):
                       d2[key]['originalLabel']='Limpia'
                    else:
                       d2[key]['originalLabel']='Desconocido'
                       #SrcIP is not in infectadas and is not in limpias
                if ((d2[key]['TCPEstablishedPercentage']<0.5)&(d2[key]['TCPNotEstablishedPercentage']<0.5)&(d2[key]['UDPEstablishedPercentage']<0.5)&(d2[key]['UDPNotEstablishedPercentage']<0.5)):
                    d2[key]['assignedLabel']='Limpia'
                    if (d2[key]['originalLabel']=='Infectada'):
                        FN+=1
                    else:
                        if (d2[key]['originalLabel']=='Limpia'):
                            TN+=1 
                else:
                    d2[key]['assignedLabel']='Infectada'
                    countInfected+=1
                    if (d2[key]['originalLabel']=='Infectada'):
                        TP+=1
                    else:
                        if (d2[key]['originalLabel']=='Limpia'):
                            FP+=1     
													    



df2['SrcAddr'] = [value['SrcAddr'] for value in d2.values()]
df2['DstAddr'] = [value['DstAddr'] for value in d2.values()]
df2['TCPEstablishedPercentage'] = [value['TCPEstablishedPercentage'] for value in d2.values()]
df2['TCPNotEstablishedPercentage'] = [value['TCPNotEstablishedPercentage'] for value in d2.values()]
df2['UDPEstablishedPercentage'] = [value['UDPEstablishedPercentage'] for value in d2.values()]
df2['UDPNotEstablishedPercentage'] = [value['UDPNotEstablishedPercentage'] for value in d2.values()]
df2['cantTCPE'] = [value['cantTCPE'] for value in d2.values()]
df2['cantTCPNE'] = [value['cantTCPNE'] for value in d2.values()]
df2['cantUDPE'] = [value['cantUDPE'] for value in d2.values()]
df2['cantUDPNE'] = [value['cantUDPNE'] for value in d2.values()]
df2['originalLabel'] = [value['originalLabel'] for value in d2.values()]
df2['assignedLabel'] = [value['assignedLabel'] for value in d2.values()]

print("countInfected")
print(countInfected)
print("TP")
print(TP)
print("FP")
print(FP)
print("TN")
print(TN)
print("FN")
print(FN)


export_csv = df2.to_csv (r'export_dataframe-C1.csv', index = None, header=True)

