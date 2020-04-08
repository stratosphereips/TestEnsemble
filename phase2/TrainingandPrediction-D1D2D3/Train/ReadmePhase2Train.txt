Scripts description:
obtain_training_testing_forphase2.py: separate the dataset resultsFase1conrandom-dataset1-2-3.csv for training (80%) and testing(20%)

decisionForEachPairIpSrc-IPDstBasedinPercentegesofTCP-UDPconnectionsLabels.py: this scripts take a decision for each pair IPSrc-IPDst based on 
the following criteria (the decision means that the set of flows between them is part of an infection):

First, for each set of flows between a source IP and a destination IP we calculate:
- Number of flows belonging to TCP Established Connection labeled as malware and percentage of flows belonging to TCP Established Connection labeled as malware.
- Number of flows belonging to TCP NotEstablished Connection labeled as malware and percentage of flows belonging to TCP NotEstablished Connection labeled as malware.
- Number of flows belonging to UDP Established Connection labeled as malware and percentage of flows belonging to UDP Established Connection labeled as malware.
- Number of flows belonging to UDP NotEstablished Connection labeled as malware and percentage of flows belonging to UDP Not Established Connection labeled as malware.
- Number of flows belonging to OthersProtocol and states labeled as malware and percentage of flows belonging to OthersProtocol and states  labeled as malware.
  
Secondly we decide if the set of flows of each type of connection for each source IP and destination IP is malware or normal.
The criteria is if:
1)Number of flows belonging to TCP Established Connection labeled as malware > THRESHOLDCOUNTER AND percentage of flows belonging to TCP Established Connection labeled as malware > THRESHOLDPERCENTAGE
OR
2)Number of flows belonging to TCP NotEstablished Connection labeled as malware > THRESHOLDCOUNTER AND percentage of flows belonging to TCP NotEstablished Connection labeled as malware > THRESHOLDPERCENTAGE
OR
3)Number of flows belonging to UDP Established Connection labeled as malware > THRESHOLDCOUNTER AND percentage of flows belonging to UDP Established Connection labeled as malware > THRESHOLDPERCENTAGE
OR
4)Number of flows belonging to UDP NotEstablished Connection labeled as malware > THRESHOLDCOUNTER AND percentage of flows belonging to UDP NotEstablished Connection labeled as malware > THRESHOLDPERCENTAGE

THEN the set of flows between the source IP and the destination IP is labeled AS MALWARE
Else the set of flows between the source IP and the destination IP is labeled AS MALWARE

In this script we use differents values as THRESHOLD for percentege of malware flows of each type (TCPEstablished, TCPNotEstablished, UDPEstablished, UDPNotEstablished) and as THRESHOLD for counters of each types.

As results we obtain:
- A set of resulting datasets (one dataset for each pair of thresholds).
- A spreadsheet with confusion matrix values and associated metrics for each resulting dataset.

Based on the spreadsheet we can chose wich are the better threshold (better criteria) to use in this phase.

and we choose these with we obtain better results. To choose it we chose minimize FP and FN.


