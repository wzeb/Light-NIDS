import os.path
from typing import Iterator
import numpy as np
import torch
from PIL import Image
from torch.utils.data import Dataset, DataLoader, Subset, random_split
import re
from functools import reduce
from torch.utils.tensorboard import SummaryWriter as Writer
from torchvision import transforms, datasets
import torchvision as tv
from torch import nn
import torch.nn.functional as F
import time
from collections import OrderedDict
class DSCWithBNAndRelu(nn.Module):
    def __init__(self,indim,hidden,outdim,ksize,stride,padding,hasShortCut=False):
        super().__init__()
        self.hasShortCut=hasShortCut
        # 带BN及Relu的深度可分离卷积
        self.baseNet=nn.Sequential(nn.Conv2d(indim, hidden, kernel_size=1,bias=False),
                              nn.BatchNorm2d(hidden),
                              nn.ReLU(True),
                              nn.Conv2d(hidden, hidden, kernel_size=ksize, stride=stride,
                                        padding=padding,groups=hidden,bias=False),
                              nn.BatchNorm2d(hidden),
                              nn.ReLU(True),
                              nn.Conv2d(hidden, outdim, kernel_size=1,bias=False),
                              nn.BatchNorm2d(outdim),
                              )
    def forward(self,x):
        x1 =self.baseNet(x)
        if self.hasShortCut:
           return x1+x
        else:
           return x1
class myCustomerMobileNetv2(nn.Module):
    #参数为分类数：
    def __init__(self,classNum=20):
        super().__init__()
        # 带BN及Relu的深度可分离卷积
        self.features=nn.Sequential(OrderedDict([
            ('C1',nn.Sequential(nn.Conv2d(3, 32, kernel_size=3, stride=2, padding=1),nn.BatchNorm2d(32),nn.ReLU(True))),

            ('Bottleneck_1',DSCWithBNAndRelu(indim=32, hidden=32, outdim=16, ksize=3, stride=1, padding=1, hasShortCut=False)),
            ('Bottleneck_2',DSCWithBNAndRelu(indim=16, hidden=96, outdim=24, ksize=3, stride=2, padding=1, hasShortCut=False)),
            ('Bottleneck_3',DSCWithBNAndRelu(indim=24, hidden=144, outdim=24, ksize=3, stride=1, padding=1, hasShortCut=True)),

            ('Bottleneck_4',DSCWithBNAndRelu(indim=24, hidden=144, outdim=32, ksize=3, stride=2, padding=1, hasShortCut=False)),
            ('Bottleneck_5',DSCWithBNAndRelu(indim=32, hidden=192, outdim=32, ksize=3, stride=1, padding=1, hasShortCut=True)),

            ('Bottleneck_6',DSCWithBNAndRelu(indim=32, hidden=192, outdim=32, ksize=3, stride=1, padding=1, hasShortCut=True)),

            ('Bottleneck_7',DSCWithBNAndRelu(indim=32, hidden=192, outdim=64, ksize=3, stride=1, padding=1, hasShortCut=False)),
            ('Bottleneck_8',DSCWithBNAndRelu(indim=64, hidden=384, outdim=64, ksize=3, stride=1, padding=1, hasShortCut=True)),

            ('Bottleneck_9',DSCWithBNAndRelu(indim=64, hidden=384, outdim=64, ksize=3, stride=1, padding=1, hasShortCut=True)),

            ('Bottleneck_10',DSCWithBNAndRelu(indim=64, hidden=384, outdim=64, ksize=3, stride=1, padding=1, hasShortCut=True)),

            ('Bottleneck_11',DSCWithBNAndRelu(indim=64, hidden=384, outdim=96, ksize=3, stride=2, padding=1, hasShortCut=False)),
            ('Bottleneck_12',DSCWithBNAndRelu(indim=96, hidden=576, outdim=96, ksize=3, stride=1, padding=1, hasShortCut=True)),

            ('Bottleneck_13',DSCWithBNAndRelu(indim=96, hidden=576, outdim=96, ksize=3, stride=1, padding=1, hasShortCut=True)),

            ('Bottleneck_14',DSCWithBNAndRelu(indim=96, hidden=576, outdim=160, ksize=3, stride=2, padding=1, hasShortCut=False)),
            ('Bottleneck_15',DSCWithBNAndRelu(indim=160, hidden=960, outdim=160, ksize=3, stride=1, padding=1, hasShortCut=True)),

            ('Bottleneck_16',DSCWithBNAndRelu(indim=160, hidden=960, outdim=160, ksize=3, stride=1, padding=1, hasShortCut=True)),

            ('Bottleneck_17',DSCWithBNAndRelu(indim=160, hidden=960, outdim=320, ksize=3, stride=1, padding=1, hasShortCut=False)),
            ('C2',nn.Sequential(nn.Conv2d(320, 1280, kernel_size=1, stride=1, padding=0),nn.BatchNorm2d(1280),nn.ReLU(True))),
            ('GP',nn.AdaptiveAvgPool2d(1)),
            ('C3', nn.Sequential(nn.Conv2d(1280, classNum, kernel_size=1, stride=1, padding=0), nn.BatchNorm2d(classNum),nn.ReLU(True)))
        ])
        )
    def forward(self,x):
        return self.features(x)

#进行测试
myNet=myCustomerMobileNetv2()
myNet.eval()
#测试模式时nn.BatchNorm2d的batchsize可以为1
k = torch.rand(1, 3, 224, 224)
print(myNet(k).shape)