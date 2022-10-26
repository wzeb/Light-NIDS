import time
from datasets import MedBIoT_Datasets
from dA import dA, dA_params

import numpy as np
import random
import matplotlib.pyplot as plt

def gen_data():
    datasets = MedBIoT_Datasets().getDatasets()
    ftrain = open('datas\\TF\\train.txt', 'w')
    ftest = open('datas\\TF\\test-0.txt', 'w')
    trainDatas = np.empty([0, 21], dtype=float)
    testDatas = np.empty([0, 21], dtype=float)
    for datas in datasets.datasets:
        if datas.code > 3:
            continue
        mat = np.loadtxt(datas.file_loc + '_statistics.txt')
        print('train: ' + datas.file_loc)
        num = mat.shape[0] // 10 * 4
        print('select: ' + str(num))
        index = random.sample(range(mat.shape[0]), num)
        index = sorted(index)
        for i in range(mat.shape[0]):
            if i in index:
                trainDatas = np.row_stack((trainDatas, mat[i]))
            else:
                testDatas = np.row_stack((testDatas, mat[i]))
    print('trainDatas: ' + str(trainDatas.shape))
    print('testDatas: ' + str(testDatas.shape))
    np.savetxt(ftrain, trainDatas)
    np.savetxt(ftest, testDatas)
    ftrain.close()
    ftest.close()
    ####################### malware test datas ###################################
    testDatas = np.empty([0, 21], dtype=float)
    for datas in datasets.datasets:
        if datas.code <= 3:
            continue
        mat = np.loadtxt(datas.file_loc + '_statistics.txt')
        mat = mat.reshape((-1, 21))
        print(datas.file_loc)
        print('shape:' + str(mat.shape))
        num = min(1000, mat.shape[0])
        index = random.sample(range(mat.shape[0]), num)
        for i in range(num):
            testDatas = np.row_stack((testDatas, mat[index[i]]))
    f = open('datas\\TF\\test-1.txt', 'w')
    np.savetxt(f, testDatas)
    print('test-1:' + str(testDatas.shape))
    f.close()
#gen_data()




def train_a_TF():
    AD = dA(dA_params(n_visible=21, n_hidden=7, lr=0.001, corruption_level=0.0, gracePeriod=0, hiddenRatio=None))
    #### ==== train  =====
    file = 'datas\\TF\\train.txt'
    mat = np.loadtxt(file)
    print('train shape:' + str(mat.shape))
    for n in range(50):
        for i in range(mat.shape[0]):
            AD.train(mat[i])
    print('trained.')
    AD.save_model()


def run():
    AD = dA(dA_params(n_visible=21, n_hidden=7, lr=0.001, corruption_level=0.0, gracePeriod=0, hiddenRatio=None))
    #### ==== train  =====
    file = 'datas\\TF\\train.txt'
    mat = np.loadtxt(file)
    print('train shape:' + str(mat.shape))
    for n in range(50):
        for i in range(mat.shape[0]):
            AD.train(mat[i])
    print('trained.')
    #########################################
    file = 'datas\\TF\\test-0.txt'
    mat = np.loadtxt(file)
    RMSE_0 = []
    begin = time.time()
    for i in range(mat.shape[0]):
        rmse = AD.execute(mat[i])
        RMSE_0.append(rmse)
    print('use time: ' + str(time.time() - begin))
    print("size = " + str(len(RMSE_0)))
    RMSE_0 = sorted(RMSE_0)
    f = open('RMSE_0.txt', 'w')
    np.savetxt(f, RMSE_0)
    f.close()
    print('exe test0 down.')
    ########################################
    file = 'datas\\TF\\test-1.txt'
    mat = np.loadtxt(file)
    RMSE_1 = []
    for i in range(mat.shape[0]):
        rmse = AD.execute(mat[i])
        RMSE_1.append(rmse)
    RMSE_1 = sorted(RMSE_1)
    f = open('RMSE_1.txt', 'w')
    np.savetxt(f, RMSE_1)
    f.close()

run()


def pylot_eff():
    rmse0s = np.loadtxt('RMSE_0.txt')
    rmse1s = np.loadtxt('RMSE_1.txt')
    X = []
    Y = []
    left = 0
    for i in range(len(rmse0s)):
        while rmse1s[left] <= rmse0s[i]:
            left += 1
        X.append(left/len(rmse1s))
        Y.append((1+i)/len(rmse0s))
    plt.figure(figsize=(20, 20), dpi=400)
    plt.scatter(X, Y, c='black', s=5)
    plt.savefig('pylot_eff.png')

#pylot_eff()


def pylot_rmse():
    rmse0s = np.loadtxt('RMSE_0.txt')
    rmse1s = np.loadtxt('RMSE_1.txt')
    """
    for i in range(len(rmse0s)):
        if rmse0s[i] > 0.01:
            print(str(i) + ', ' + str(len(rmse0s)))
            break
    for i in range(len(rmse1s)):
        if rmse1s[i] > 0.01:
            print(str(i) + ', ' + str(len(rmse1s)))
            break
    """
    rmse1s = rmse1s[:50]
    plt.figure(figsize=(10, 10), dpi=100)
    X = np.random.rand(len(rmse0s))
    plt.scatter(X, rmse0s, c='black', s=10)
    X = np.random.rand(len(rmse1s))
    plt.scatter(X, rmse1s, c='red', s=5)
    plt.savefig('rmses.png')

#pylot_rmse()

"""
>>> %Run run_TF.py
train shape:(5855, 21)
threshold: 0.5154911588232829
test-0 shape:(5855, 21)
5774/5855
use time: 0.8306665420532227
test-1 shape:(17993, 21)
mn: 0.0036037309943590776
17991/17993
use time: 2.557079553604126
"""


def test():
    AD = dA(dA_params(n_visible=21, n_hidden=7, lr=0.001, corruption_level=0.0, gracePeriod=0, hiddenRatio=None))
    #### ==== train  =====
    file = 'train.txt'
    mat = np.loadtxt(file)
    print('train shape:' + str(mat.shape))
    for n in range(50):
        for i in range(mat.shape[0]):
            AD.train(mat[i])
    #### ==== threshold  =====


    thresholds = []
    for i in range(mat.shape[0]):
        thresholds.append(AD.execute(mat[i]))
    X = np.random.rand(len(thresholds))
    X = np.sort(X)
    datasets = MedBIoT_Datasets().getDatasets()
    for datas in datasets.datasets:
        if datas.code != 7:
            continue
        RMSEs = []
        mat = np.loadtxt(datas.file_loc + '_statistics.txt')
        for i in range(mat.shape[0]):
            rmse = AD.execute(mat[i])
            #if rmse < 10:
            RMSEs.append(rmse)
        with open('loglog.txt', 'w') as log:
            for a in RMSEs:
                log.write(str(a) + '\n')
        plt.figure(figsize=(20, 20), dpi=400)
        plt.scatter(X, thresholds, c='black', s=10)
        XX = sorted(np.random.rand(len(RMSEs)))
        plt.scatter(XX, RMSEs, c='red', s=1)
        plt.savefig('output\\paper\\' + datas.file_loc.split('\\')[-1] + '.png')
        #plt.show()
#gen_data()
#test()

#train_a_TF()