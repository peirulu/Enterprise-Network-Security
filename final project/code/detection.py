#!/usr/bin/env python
# coding: utf-8

# In[1]:


import json
import copy

sysmon=list()
read both malicious and benign log
for line in open("normal.json",'r',encoding="utf-8"):
    temp=json.loads(line)
    if temp['_source']['winlog']['provider_name']=='Microsoft-Windows-Sysmon':
        sysmon.append(temp['_source'])

for line in open("malicious.json",'r',encoding="utf-8"):
    temp=json.loads(line)
    if temp['_source']['winlog']['provider_name']=='Microsoft-Windows-Sysmon':
        sysmon.append(temp['_source'])


# In[ ]:





# In[2]:


data=list()
ancestor=list()
pid_executable = dict()

for logs in sysmon:
    row=list()
    time=logs['@timestamp']
    event_id=logs['winlog']['event_id']
    record_id=logs['winlog']['record_id']
    
    try:
        process_pid=logs['process']['pid']
    except:
        process_pid=-1
    try:
        parent_pid=logs['process']['parent']['pid']
    except:
        parent_pid=-1
    try:
        process_executable = logs['process']['executable']
    except:
        process_executable = ""
    row=[time,event_id,record_id,process_pid,parent_pid,process_executable]#,process_executable]
    if parent_pid !=-1:
        ancestor.append(row)
        pid_executable[(record_id,process_pid)]= process_executable
    data.append(row)
data.sort(key=lambda x:x[2])


# In[3]:



pids=list()
parent_exist=list()
for i in range(len(ancestor)):
    pids.append(ancestor[i][2:5])


# In[4]:


pids.sort(reverse=True)
vertical_relationship=dict()
for i in range(len(pids)):
    for j in range(i+1,len(pids)):
        if pids[i][2]==pids[j][1]:
            k=tuple(pids[j][:2])
            v=tuple(pids[i][:2])
            #print("k=",k, " ,v=",v)
            try:
                vertical_relationship[k].append(v)
            except:
                vertical_relationship[k]=[v]
            break
        


# In[5]:


for k,v in vertical_relationship.items():
    print("@@@@@@@@@@@@@ ",k," : ",pid_executable[k]," @@@@@@@@@@@@@ ")
    for element in v:
        print(element)
    print("----------------------")


# In[6]:


from graphviz import Digraph
visit=[]
parent_key=list(vertical_relationship.keys())
parent_key.sort()
for i in range(len(parent_key)):
    print("#############THIS IS ",i+1," LOOPS ######################")
    q=[parent_key[i]]
    if parent_key[i] in visit:
        continue
    dot = Digraph(comment='Log')
    acrobat_flag = False
    exe = pid_executable[q[0]].split("\\")[-1]
    executables = [exe]
    while q:
        current=q.pop()
        visit.append(current)
        if "AcroRd32.exe" in pid_executable[current]:
            acrobat_flag =True
        try:
            for child in vertical_relationship[current]:
                parent_exe = pid_executable[current].split("\\")[-1]
                child_exe = pid_executable[child].split("\\")[-1]
                start=str(current[0])+"_"+parent_exe
                end = str(child[0])+"_"+child_exe
                dot.edge(start,end)
                q.append(child)
                visit.append(child)
                executables.append(child_exe)
        except:
            continue
    print(dot.source)
    #filename="detection_"+str(i)+".gv"
    if acrobat_flag:
        black_list = ["rundll.exe","cmd.exe","powershell.exe"]
        filename = "benign"+str(i+1)
        print("******** Executable launch by acrobat reader ********")
        for element in list(set(executables)):
            print(element)
            if element in black_list:
                filename="malicious"+str(i+1)
        print("*****************************************************")
        dot.render("./pdf_detection_result/"+filename, view=True)
    #break
        


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




