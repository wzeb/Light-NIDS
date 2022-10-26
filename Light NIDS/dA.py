# Copyright (c) 2017 Yusuke Sugomori
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Portions of this code have been adapted from Yusuke Sugomori's code on GitHub: https://github.com/yusugomori/DeepLearning

import sys
import numpy
from TrafficFilter.utils import *
import json
import pickle
import numpy as np

class dA_params:
    def __init__(self,n_visible = 5, n_hidden = 3, lr=0.001, corruption_level=0.0, gracePeriod = 10000, hiddenRatio=None):
        self.n_visible = n_visible# num of units in visible (input) layer
        self.n_hidden = n_hidden# num of units in hidden layer
        self.lr = lr
        self.corruption_level = corruption_level
        self.gracePeriod = gracePeriod
        self.hiddenRatio = hiddenRatio

class dA:
    def __init__(self, params):
        self.params = params

        if self.params.hiddenRatio is not None:
            self.params.n_hidden = int(numpy.ceil(self.params.n_visible*self.params.hiddenRatio))

        # for 0-1 normlaization
        self.norm_max = numpy.ones((self.params.n_visible,)) * -numpy.Inf
        self.norm_min = numpy.ones((self.params.n_visible,)) * numpy.Inf
        self.n = 0

        self.rng = numpy.random.RandomState(1234)

        a = 1. / self.params.n_visible
        self.W = numpy.array(self.rng.uniform(  # initialize W uniformly
            low=-a,
            high=a,
            size=(self.params.n_visible, self.params.n_hidden)))
        # n_visible * n_hidden [-a,a]均匀分布

        self.hbias = numpy.zeros(self.params.n_hidden)  # initialize h bias 0
        self.vbias = numpy.zeros(self.params.n_visible)  # initialize v bias 0
        self.W_prime = self.W.T # T : 转置


    def get_corrupted_input(self, input, corruption_level):
        assert corruption_level < 1

        # numpy.random.RandomState.binomial(n, p, size)
        # 从二项式分布P(x=k) = C(n,k)*p^k*(1-p)^{n-k}中采样size次
        # 返回size的数组，每个数表示每轮实验(n次)中事件发生(概率p)的次数
        # 1-corruption_level的概率将输入的对应位置置0
        return self.rng.binomial(size=input.shape,
                                 n=1,
                                 p=1 - corruption_level) * input
    # Encode
    def get_hidden_values(self, input):
        return sigmoid(numpy.dot(input, self.W) + self.hbias)

    # Decode
    def get_reconstructed_input(self, hidden):
        return sigmoid(numpy.dot(hidden, self.W_prime) + self.vbias)

    def train(self, x):
        self.n = self.n + 1
        # update norms
        self.norm_max[x > self.norm_max] = x[x > self.norm_max]
        self.norm_min[x < self.norm_min] = x[x < self.norm_min]

        # 0-1 normalize
        x = (x - self.norm_min) / (self.norm_max - self.norm_min + 0.0000000000000001)

        if self.params.corruption_level > 0.0:
            print("******* self.params.corruption_level  = ", self.params.corruption_level)
            tilde_x = self.get_corrupted_input(x, self.params.corruption_level)
        else:
            tilde_x = x
        y = self.get_hidden_values(tilde_x)
        z = self.get_reconstructed_input(y)

        L_h2 = x - z
        L_h1 = numpy.dot(L_h2, self.W) * y * (1 - y)

        L_vbias = L_h2
        L_hbias = L_h1
        L_W = numpy.outer(tilde_x.T, L_h1) + numpy.outer(L_h2.T, y)

        self.W += self.params.lr * L_W
        self.hbias += self.params.lr * numpy.mean(L_hbias, axis=0)
        self.vbias += self.params.lr * numpy.mean(L_vbias, axis=0)
        return numpy.sqrt(numpy.mean(L_h2**2)) #the RMSE reconstruction error during training

    def save_model(self):
        f = open('TF_model', 'wb')
        ps = []
        ps.append(self.params)
        ps.append(self.n)
        ps.append(self.norm_min)
        ps.append(self.norm_max)
        ps.append(self.rng)
        ps.append(self.W)
        ps.append(self.hbias)
        ps.append(self.vbias)
        ps.append(self.W_prime)
        pickle.dump(ps, f)
        f.close()

    def read_mode(self):
        f = open('TF_model', 'rb')
        ps = pickle.load(f)
        self.params = ps[0]
        self.n = ps[1]
        self.norm_min = ps[2]
        self.norm_max = ps[3]
        self.rng = ps[4]
        self.W = ps[5]
        self.hbias = ps[6]
        self.vbias = ps[7]
        self.W_prime = ps[8]
        f.close()

    def reconstruct(self, x):
        y = self.get_hidden_values(x)
        z = self.get_reconstructed_input(y)
        return z

    def execute(self, x): #returns MSE of the reconstruction of x
        if self.n < self.params.gracePeriod:
            return 0.0
        else:
            # 0-1 normalize
            x = (x - self.norm_min) / (self.norm_max - self.norm_min + 0.0000000000000001)
            z = self.reconstruct(x)
            rmse = numpy.sqrt(((x - z) ** 2).mean()) #RMSE
            return rmse

    def inGrace(self):
        return self.n < self.params.gracePeriod
