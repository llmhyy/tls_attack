# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'template.ui'
#
# Created by: PyQt5 UI code generator 5.11.2
#
# WARNING! All changes made in this file will be lost!
import os
import re
import sys
import json
import math
import time
import fnmatch
import traceback
import subprocess
from functools import partial

import numpy as np
from PyQt5 import QtCore, QtWidgets, QtGui
from keras.models import load_model
from matplotlib.backends.backend_qt5agg import (FigureCanvas, NavigationToolbar2QT as NavigationToolbar)
from matplotlib.figure import Figure
from ruamel.yaml import YAML

import tensorflow as tf
from keras.backend.tensorflow_backend import set_session
tf_config = tf.ConfigProto()
tf_config.gpu_options.allow_growth = True  # dynamically grow the memory used on the GPU
tf_config.log_device_placement = True  # to log device placement (on which device the operation ran)
# (nothing gets printed in Jupyter, only if you run it standalone)
sess = tf.Session(config=tf_config)
set_session(sess)  # set this TensorFlow session as the default session for Keras

sys.path.append(os.path.join('..','rnn-model'))
import utils_datagen as utilsDatagen
import utils_metric as utilsMetric
sys.path.append(os.path.join('..','feature-extraction'))
import utils as utilsFeatureExtract

import config

# Initialize a yaml object for reading and writing yaml files
yaml = YAML(typ='rt') # Round trip loading and dumping
yaml.preserve_quotes = True
yaml.indent(mapping=4, sequence=4)

# BASE WIDGET FOR PLOTTING MATPLOTLIB GRAPHS
class PlotWidget(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        QtWidgets.QWidget.__init__(self, *args, **kwargs)
        self.setLayout(QtWidgets.QVBoxLayout())

    def add_canvas(self, canvas):
        self.canvas = canvas
        self.toolbar = NavigationToolbar(self.canvas, self)
        self.toolbar.setMaximumSize(QtCore.QSize(414, 18))
        self.toolbar.updateGeometry()
        self.layout().addWidget(self.toolbar)
        self.layout().addWidget(self.canvas)
        self.layout().setContentsMargins(0,0,0,0)
        self.layout().setSpacing(0)

# MATPLOTLIB CANVAS WIDGET FOR PLOTTING PACKET DIMENSIONS
class DimCanvas(FigureCanvas):
    def __init__(self):
        self.bar_width = 0.3
        self.opacity = 0.5

        fig = Figure(figsize=(15.51, 2.31))
        FigureCanvas.__init__(self, fig)
        self.dim_fig = self.figure
        self.dim_fig.subplots_adjust(bottom=0.5, left=0.05, right=0.95)
        self.dim_ax = self.dim_fig.subplots()
        self.dim_ax2 = self.dim_ax.twinx()

    def plot(self, packet_num, data):
        self.dim_ax.clear()
        self.dim_ax2.clear()

        predict = data['predict']
        true = data['true']
        sqerr = data['squared_error']
        dim_names = data['dim_names']
        ndim = len(dim_names)
        index = [i for i in range(ndim)]

        self.dim_ax.bar(index, predict[packet_num,:], self.bar_width,
                            alpha=self.opacity, color='b', label='Predict')
        self.dim_ax.bar([i+self.bar_width for i in index], true[packet_num,:], self.bar_width,
                            alpha=self.opacity, color='r', label='True')
        self.dim_ax.set_xticks([i+(self.bar_width/2) for i in index])
        self.dim_ax.set_xticklabels(dim_names, rotation='vertical', fontsize=6)
        xticklabels = self.dim_ax.get_xticklabels()
        switch = False
        picker = 0
        nice_color = ['#466365', '#B49A67','#CEB3AB','#C4C6E7','#BAA5FF']
        for i in range(1, len(xticklabels)):
            xticklabels_curr_str = xticklabels[i].get_text()
            xticklabels_prev_str = xticklabels[i-1].get_text()
            curr_idx = xticklabels_curr_str.find('-')
            prev_idx = xticklabels_prev_str.find('-')
            if curr_idx!=-1 and prev_idx!=-1:
                if xticklabels_curr_str[curr_idx-4:curr_idx]==xticklabels_prev_str[prev_idx-4:prev_idx]:
                    if not switch:
                        xticklabels[i].set_color(nice_color[picker%len(nice_color)])
                        xticklabels[i-1].set_color(nice_color[picker%len(nice_color)])
                    else:
                        xticklabels[i].set_color(nice_color[picker%len(nice_color)])
                else:
                    picker+=1
            elif prev_idx!=-1:
                switch=False
                picker+=1
        self.dim_ax.legend(loc='upper left', fontsize=7)
        self.dim_ax.set_ylabel('Predict/True output')

        self.dim_ax2.plot(index, sqerr[packet_num], color='#000000', linewidth=0.7)
        self.dim_ax2.set_ylabel('Sq err')
        self.dim_ax.set_title('Packet No. {}'.format(packet_num+1))

        self.draw()

# MATPLOTLIB CANVAS WIDGET FOR PLOTTING PACKET ACCURACY
class AccCanvas(FigureCanvas):
    def __init__(self, dimcanvas):
        fig = Figure(figsize=(2.81, 6.21))
        FigureCanvas.__init__(self, fig)
        self.acc_fig = self.figure
        self.acc_ax = self.acc_fig.subplots()
        self.dimcanvas = dimcanvas
        self.maxpackettoshow = 50
        self.currentpage = 0
        self.line = None
        self.reddot = None
        self.greydot = None

    def plot(self, data):
        self.dimcanvas.dim_ax.clear()
        self.dimcanvas.dim_ax2.clear()
        self.dimcanvas.draw()
        self.acc_ax.clear()

        # Save data into class's attribute first
        self.data = data
        self.acc = self.data['acc']
        self.mean_acc = self.data['mean_acc']
        self.pktlen_mask = self.data['pktlen_mask']
        self.maxpage = math.ceil(self.acc.count()/self.maxpackettoshow) - 1


        self._plot()

    def _plot(self):
        self.acc_ax.clear()

        # Setup matplotlib axes and fig
        self.acc_ax.invert_yaxis()
        self.acc_ax.set_title('Mean Acc: {}'.format(self.mean_acc))
        self.acc_ax.set_xlabel('Acc')
        self.acc_ax.set_xlim(0.0, 1.0)
        self.annot = self.acc_ax.annotate('', xy=(0.5,0.5), xytext=(-1, 5), textcoords='offset points', horizontalalignment='center')
        self.annot.set_visible(False)
        self.acc_fig.canvas.mpl_connect('pick_event', self.on_pick)
        self.acc_fig.canvas.mpl_connect('motion_notify_event', self.hover)

        pkt_num = []
        acc = []
        pktlen_mask = []
        try:
            for i in range(self.currentpage*self.maxpackettoshow, (self.currentpage+1)*self.maxpackettoshow):
                pkt_num.append(i+1)
                acc.append(self.acc[i])
                pktlen_mask.append(self.pktlen_mask[i])
        except IndexError:
            # Reached end of array
            pass

        self.line, = self.acc_ax.plot(acc, pkt_num)
        for i,pkt_acc in enumerate(acc):
            if pktlen_mask[i]:
                self.greydot = self.acc_ax.plot(pkt_acc, pkt_num[i], 'o', picker=2.0, markersize=3, color='grey')
            else:
                self.reddot = self.acc_ax.plot(pkt_acc, pkt_num[i], 'ro', picker=2.0, markersize=3)
        self.draw()

    def _plot_next(self):
        self.currentpage = min(self.currentpage+1, self.maxpage)
        self._plot()

    def _plot_previous(self):
        self.currentpage = max(self.currentpage-1, 0)
        self._plot()

    def on_pick(self, event):
        packet_num = int(round(event.mouseevent.ydata)) - 1
        self.dimcanvas.plot(packet_num, self.data)

    def update_annot(self, idx):
        x,y = self.line.get_data()
        self.annot.xy = (x[idx['ind'][0]], y[idx['ind'][0]])
        text = '{}'.format(y[idx['ind'][0]])
        self.annot.set_text(text)

    def hover(self, event):
        vis = self.annot.get_visible()
        if event.inaxes == self.acc_ax:
            is_contain, idx = self.line.contains(event)
            if is_contain:
                self.update_annot(idx)
                self.annot.set_visible(True)
                self.draw_idle()
            else:
                if vis:
                    self.annot.set_visible(False)
                    self.draw_idle()

class Ui_MainWindow(object):
    def __init__(self, pcap_dirs, model_dirs, feature_dirs):
        self.pcap_dirs = pcap_dirs
        self.model_dirs = model_dirs
        self.feature_dirs = feature_dirs

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1838, 963)
        MainWindow.setStyleSheet("""
            #centralwidget{
                background-color: rgb(74, 136, 204)
            }
            QMessageBox{
                background-color: rgb(255,255,255);
            }
            #background, #predictsOnLabel, #searchCriteriaLabel{
                background-color: rgb(212, 217, 217);
            }
            QComboBox{
                background-color: rgb(255, 255, 255);
            }
            #searchButton, #settingButton{
                background-color: rgb(255, 255, 255);
            }
            QListWidget{
                background-color: rgb(255, 255, 255);
            }
            QTableWidget{
                background-color: rgb(255, 255, 255);
            }
            """)
        
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        self.background = QtWidgets.QLabel(self.centralwidget)
        self.background.setText("")
        self.background.setObjectName("background")
        
        self.vbox1 = QtWidgets.QVBoxLayout()
        self.vbox1.addWidget(self.background)
        self.centralwidget.setLayout(self.vbox1)

        self.chooseModel = QtWidgets.QComboBox()
        self.chooseModel.setEditable(False)
        self.chooseModel.setObjectName("chooseModel")
        self.chooseModel.addItem("- Model type -")
        for m in config.model.keys():
            self.chooseModel.addItem('{} model'.format(m.title()))

        self.predictsOnLabel = QtWidgets.QLabel()
        self.predictsOnLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.predictsOnLabel.setObjectName("predictsOnLabel")
        self.predictsOnLabel.setText('predicts on')
        
        self.chooseTraffic = QtWidgets.QComboBox()
        self.chooseTraffic.setObjectName("chooseTraffic")
        self.chooseTraffic.addItem("- Traffic type -")
        for f in config.features.keys():
            self.chooseTraffic.addItem('{} (train)'.format(f.title()))
            self.chooseTraffic.addItem('{} (val)'.format(f.title()))

        self.searchCriteriaLabel = QtWidgets.QLabel()
        self.searchCriteriaLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.searchCriteriaLabel.setObjectName("searchCriteriaLabel")
        self.searchCriteriaLabel.setText('Search traffic with acc score between')

        self.lowerboundLineEdit = QtWidgets.QLineEdit()
        self.lowerboundLineEdit.setObjectName('lowerBound')
        self.lowerboundLineEdit.setPlaceholderText('enter btw 0.0-1.0')
        self.lowerboundLineEdit.setText('0.0')

        self.andLabel = QtWidgets.QLabel()
        self.andLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.andLabel.setObjectName('andLabel')
        self.andLabel.setText('and')

        self.upperboundLineEdit = QtWidgets.QLineEdit()
        self.upperboundLineEdit.setObjectName('upperBound')
        self.upperboundLineEdit.setPlaceholderText('enter btw 0.0-1.0')
        self.upperboundLineEdit.setText('1.0')

        self.searchButton = QtWidgets.QPushButton()
        self.searchButton.setObjectName("searchButton")
        self.searchButton.setText('Search')
        self.searchButton.clicked.connect(self.onSearch)
        
        self.settingButton = QtWidgets.QPushButton()
        self.settingButton.setObjectName("settingButton")
        self.settingButton.setText('Settings')

        self.hbox1 = QtWidgets.QHBoxLayout()
        self.hbox1.addWidget(self.chooseModel)
        self.hbox1.addWidget(self.predictsOnLabel)
        self.hbox1.addWidget(self.chooseTraffic)
        self.hbox1.addStretch(1)
        self.hbox1.addWidget(self.searchCriteriaLabel)
        self.hbox1.addWidget(self.lowerboundLineEdit)
        self.hbox1.addWidget(self.andLabel)
        self.hbox1.addWidget(self.upperboundLineEdit)
        self.hbox1.addWidget(self.searchButton)
        self.hbox1.addWidget(self.settingButton)

        self.trafficLabel = QtWidgets.QLabel()
        self.trafficLabel.setStyleSheet("background-color: rgb(90, 145, 205);\ncolor: rgb(255, 255, 255);")
        self.trafficLabel.setTextFormat(QtCore.Qt.PlainText)
        self.trafficLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.trafficLabel.setWordWrap(True)
        self.trafficLabel.setObjectName("trafficLabel")
        self.trafficLabel.setText('Traffic')
        
        self.listWidget = QtWidgets.QListWidget()
        self.listWidget.setObjectName("listWidget")

        self.vbox3 = QtWidgets.QVBoxLayout()
        self.vbox3.addWidget(self.trafficLabel)
        self.vbox3.addWidget(self.listWidget)
        self.vbox3.setSpacing(0)
        self.vbox3.setContentsMargins(0,0,0,0)
        
        self.dimGraph = DimCanvas()
        self.dimGraphWidget = PlotWidget()
        self.dimGraphWidget.add_canvas(self.dimGraph)
        self.dimGraph.setParent(self.dimGraphWidget)

        self.tableWidget = QtWidgets.QTableWidget()
        self.tableWidget.setShowGrid(True)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(0)
        self.tableWidget.setRowCount(0)
        self.tableWidget.verticalHeader().setVisible(True)
        # Override QtTableWidget's cellClicked
        def plotDimGraphOnClickTable(row, column):
            self.dimGraph.plot(row, self.data)
        self.tableWidget.cellClicked.connect(plotDimGraphOnClickTable)

        self.accGraph = AccCanvas(self.dimGraph)
        self.accGraphWidget = PlotWidget()
        self.accGraphWidget.add_canvas(self.accGraph)
        self.accGraph.setParent(self.accGraphWidget)

        self.leftButtonForAccGraph = QtWidgets.QPushButton()
        self.leftButtonForAccGraph.setObjectName('leftButtonAccGraph')
        self.leftButtonForAccGraph.setIcon(QtGui.QIcon(os.path.join('icons','leftarrow.png')))
        self.leftButtonForAccGraph.clicked.connect(self.accGraph._plot_previous)

        self.rightButtonForAccGraph = QtWidgets.QPushButton()
        self.rightButtonForAccGraph.setObjectName('rightButtonAccGraph')
        self.rightButtonForAccGraph.setIcon(QtGui.QIcon(os.path.join('icons', 'rightarrow.png')))
        self.rightButtonForAccGraph.clicked.connect(self.accGraph._plot_next)

        self.hbox2 = QtWidgets.QHBoxLayout()
        self.hbox2.addWidget(self.leftButtonForAccGraph)
        self.hbox2.addWidget(self.rightButtonForAccGraph)

        self.vbox4 = QtWidgets.QVBoxLayout()
        self.vbox4.addWidget(self.accGraphWidget, 9)
        self.vbox4.addLayout(self.hbox2, 1)

        self.hsplitter1 = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.hsplitter1.addWidget(self.tableWidget)
        # self.hsplitter1.addWidget(self.accGraphWidget)
        self.vbox4_widget = QtWidgets.QWidget()
        self.vbox4_widget.setLayout(self.vbox4)
        self.hsplitter1.addWidget(self.vbox4_widget)
        self.hsplitter1.setStretchFactor(0, 7)
        self.hsplitter1.setStretchFactor(1, 3)

        self.vsplitter1 = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        self.vsplitter1.addWidget(self.hsplitter1)
        self.vsplitter1.addWidget(self.dimGraphWidget)
        self.vsplitter1.setStretchFactor(0, 4.5)
        self.vsplitter1.setStretchFactor(1, 5.5)

        self.hsplitter2 = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.vbox3_widget = QtWidgets.QWidget()
        self.vbox3_widget.setLayout(self.vbox3)
        self.hsplitter2.addWidget(self.vbox3_widget)
        self.hsplitter2.addWidget(self.vsplitter1)
        self.hsplitter2.setStretchFactor(0, 2.5)
        self.hsplitter2.setStretchFactor(1, 7.5)
        
        self.vbox2 = QtWidgets.QVBoxLayout()
        self.vbox2.addLayout(self.hbox1, 1)
        self.vbox2.addWidget(self.hsplitter2, 9)
        self.background.setLayout(self.vbox2)

        MainWindow.setCentralWidget(self.centralwidget)

    def onSearch(self):
        # Clear the List Widget, Table Widget, Dim Graph, Acc Graph
        self.listWidget.clear()
        self.tableWidget.setRowCount(0)
        self.dimGraph.dim_ax.clear()
        self.dimGraph.dim_ax2.clear()
        self.accGraph.acc_ax.clear()
        self.dimGraph.draw()
        self.accGraph.draw()

        # Get model name and load model
        try:
            self.model_name = str(self.chooseModel.currentText()).lower().replace(" model", "")
            model_dir = os.path.join(self.model_dirs, config.model[self.model_name])
            print('Using model from {}'.format(model_dir))
            self.model = load_model(model_dir)
        except FileNotFoundError:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Model {} not found in directory path {}. Check config.py'.format(self.model_name))
            return
        except KeyError:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Model {} is not listed in the configuration file. Check config.py'.format(self.model_name))
            return
        except Exception as e:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Serious error. Check console for error message')
            print(e)
            return

        SPLIT_RATIO = 0.05
        SEED = 2019
        SEQUENCE_LEN = 100
        FEATURE_FILENAME = 'features_tls_*.csv'
        FEATUREINFO_FILENAME = 'features_info_*.csv'
        PCAPNAME_FILENAME = 'pcapname_*.csv'
        
        try:
            tmp = str(self.chooseTraffic.currentText()).lower().split('(')
            self.dataset_name = tmp[0].strip()
            self.split_name = tmp[1].rstrip(')')
            self.feature_dir = os.path.join(self.feature_dirs,config.features[self.dataset_name])
            filenames = os.listdir(self.feature_dir)
        except FileNotFoundError:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Dataset {} not found in directory path {}. Check config.py'.format(self.dataset_name, self.feature_dir))
            return
        except KeyError:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Dataset {} is not listed in the configuration file. Check config.py'.format(self.dataset_name))
            return
        except IndexError:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Dataset {} is not an appropriate option. Try again'.format(self.dataset_name))
            return
        except Exception as e:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Serious error. Check console for error message')
            traceback.print_exc()
            return

        # Load the train/test indexes from split
        try:
            self.featurecsv_dir = os.path.join(self.feature_dir, fnmatch.filter(filenames, FEATURE_FILENAME)[0])
        except IndexError:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Feature file {} not found in directory path {}. Did you remember to run file_joiner.py?'.format(FEATURE_FILENAME, self.feature_dir))
            return

        # Get the number of lines in a file to determine split
        with open(self.featurecsv_dir) as f:
            for i, line in enumerate(f):
                pass
            line_count = i+1
        train_idx, test_idx = utilsDatagen.split_train_test(line_count, SPLIT_RATIO, SEED)
        print('line count: {}'.format(line_count))
        print('train idx: {}'.format(len(train_idx)))
        print('test idx: {}'.format(len(test_idx)))
        if self.split_name == 'train':
            dataset_idx = train_idx
        elif self.split_name == 'val':
            dataset_idx = test_idx

        # Load the pcap filenames from train/test indexes
        self.pcapname_dir = os.path.join(self.feature_dir, fnmatch.filter(filenames, PCAPNAME_FILENAME)[0])
        with open(self.pcapname_dir) as f:
            lines = f.readlines()
            dataset_idx = sorted(dataset_idx)
            self.pcap_filenames = [lines[idx].strip() for idx in dataset_idx]

        # Load the dimension names
        self.featureinfo_dir = os.path.join(self.feature_dir, fnmatch.filter(filenames, FEATUREINFO_FILENAME)[0])
        self.dim_names = []
        with open(self.featureinfo_dir, 'r') as f:
            features_info = f.readlines()[1:] # Ignore header
            for row in features_info:
                split_row = row.split(',')
                network_layer, tls_protocol, dim_name, feature_type, feature_enum_value = split_row[0].strip(), split_row[1].strip(), split_row[2].strip(), split_row[3].strip(), split_row[4].strip()

                if 'Enum' in feature_type:
                    dim_name = dim_name+'-'+feature_enum_value
                if 'TLS' in network_layer:
                    dim_name = '('+tls_protocol+')'+dim_name
                self.dim_names.append(dim_name)

        # Obtain the lower and upper bound of acc for search criteria
        try:
            lowerBound = float(self.lowerboundLineEdit.text())
            upperBound = float(self.upperboundLineEdit.text())

            if lowerBound > upperBound:
                QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Lowerbound value must be smaller than upperbound value'.format(self.dataset_name))
                return

        except ValueError:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Please input appropriate values between 0.0 and 1.0')
            return

        def filterTraffic(lowerbound, upperbound):
            def filterTraffic2(x, lowerbound, upperbound):
                if x >= lowerbound and x <= upperbound:
                    return True
            return partial(filterTraffic2, lowerbound=lowerbound, upperbound=upperbound)

        self.filter_fn = filterTraffic(lowerBound, upperBound)

        # Load the traffic into ListWidget
        try:
            self.loadTraffic()
        except AttributeError as e:
            print(e)

    def loadTraffic(self):
        try:
            pcap_dir = os.path.join(self.pcap_dirs, config.pcapfiles[self.dataset_name])
        except KeyError:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Pcap directory for dataset {} is not listed in the configuration file. Check config.py'.format(self.dataset_name))
            return

        try:
            results_dir = os.path.join(self.model_dirs, config.results[self.model_name][self.dataset_name][self.split_name])
        except KeyError:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Accuracy results directory for model {} and dataset {} is not listed in the configuration file. Check config.py'.format(self.model_name, self.dataset_name))
            return

        try:
            with open(results_dir) as f:
                mean_acc_for_all_traffic = [float(l.strip()) for l in f.readlines()]

            # Get the dataset from the pcap directory and add to ListWidget
            count = 0
            normalized_pcap_filenames = [os.path.normpath(i) for i in self.pcap_filenames]
            zipped_name_acc = zip(normalized_pcap_filenames, mean_acc_for_all_traffic)
            start = time.time()
            pcap_dir_files = []
            for root,dirs,files in os.walk(pcap_dir):
                for f in files:
                    if f.endswith('.pcap'):
                        pcap_dir_files.append(os.path.normpath(os.path.join(root,f)))
            if len(pcap_dir_files) == 0:
                QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Pcap directory {} for dataset {} does not contain any pcap files.'.format(pcap_dir ,self.dataset_name))
                return

            sorted_pcap_dir_files = sorted(pcap_dir_files)
            sorted_zipped_name_acc = sorted(zipped_name_acc)
            pointer = 0

            self.full_path_list = []
            for fullpath in sorted_pcap_dir_files:
                fail_count = 0
                for i in range(pointer, len(sorted_zipped_name_acc)):
                    name,acc = sorted_zipped_name_acc[i]
                    if name in fullpath:
                        if self.filter_fn(acc):
                            # print('THIS IS THE ACC {}'.format(acc))
                            # pf
                            filename = fullpath.split(os.path.sep)[-1]
                            item = QtWidgets.QListWidgetItem(filename)
                            item.setToolTip(fullpath)
                            self.listWidget.addItem(item)
                            self.full_path_list.append(fullpath)
                            pointer = i+1
                            count+=1
                            break
                        else:
                            pointer+=1
                    else:
                        fail_count+=1

                    if fail_count>=3:
                        break
            print('Time taken to search: {}'.format(time.time()-start))
            print('{} traffic loaded into ListWidget'.format(count))
            self.listWidget.itemClicked.connect(self.onClickTraffic)

        except FileNotFoundError as e:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', e)
            return

    def onClickTraffic(self, item):
        # Load pcap table
        self.selected_pcapfile = self.full_path_list[self.listWidget.currentRow()]
        if self.selected_pcapfile == 0:
            return
        self.loadPcapTable()
        
        # Generate features from PCAP file
        ENUMS_FILENAME = 'enums_ref.yml'
        with open(os.path.join(self.feature_dirs, '..', ENUMS_FILENAME)) as f:
            enums = yaml.load(f)
        try:
            tcp_features = utilsFeatureExtract.extract_tcp_features(self.selected_pcapfile, limit=1000)
            tls_features = utilsFeatureExtract.extract_tslssl_features(self.selected_pcapfile, enums, limit=1000)
        except (KeyError, AttributeError, TypeError):
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Feature extraction failed. Choose another traffic')
            return
        traffic_features = np.concatenate((np.array(tcp_features), np.array(tls_features)), axis=1)
        traffic_features = traffic_features.reshape(1, *traffic_features.shape)     # Batchify the traffic features
        
        # Preprocess the features
        SEQUENCE_LEN = 1000
        MINMAX_FILENAME = 'features_minmax_ref.csv'
        try:
            with open(os.path.join(self.feature_dir,'..','..',MINMAX_FILENAME)) as f:
                min_max_feature_list = json.load(f)
            min_max_feature = (np.array(min_max_feature_list[0]), np.array(min_max_feature_list[1]))
        except FileNotFoundError:
            print('Error: min-max feature file cannot be found in the extracted-features directory of the selected database')
            return
        norm_fn = utilsDatagen.normalize(2, min_max_feature)
        selected_seqlen = len(traffic_features[0])
        selected_input, selected_target = utilsDatagen.preprocess_data(traffic_features, pad_len=SEQUENCE_LEN, norm_fn=norm_fn)

        # Compute metrics for GUI 
        self.data = {}
        selected_predict = self.model.predict_on_batch(selected_input)
        # Calculate metrics with batchified data
        selected_acc_padded = utilsMetric.calculate_acc_of_traffic(selected_predict, selected_target)
        selected_sqerr_padded = utilsMetric.calculate_squared_error_of_traffic(selected_predict, selected_target)

        # De-batchify the data
        selected_predict = np.squeeze(selected_predict)
        selected_target = np.squeeze(selected_target)

        upper_bound_pktlen = 100
        selected_acc_padded = np.squeeze(selected_acc_padded)  # De-batchify the data
        # Mask with true sequence length
        selected_acc_masked_by_seqlen = np.ma.array(selected_acc_padded)
        selected_acc_masked_by_seqlen[selected_seqlen:] = np.ma.masked
        # Mask with packet length smaller than upper bound
        pktlen_min, pktlen_max = min_max_feature[0][7], min_max_feature[1][7]
        selected_pktlen = selected_target[:,7]
        selected_pktlen = utilsDatagen.denormalize(selected_pktlen, pktlen_min, pktlen_max)
        selected_pktlen_mask = selected_pktlen <= upper_bound_pktlen
        selected_acc_masked_by_seqlen_and_pktlen = np.ma.array(selected_acc_masked_by_seqlen, copy=True)
        selected_acc_masked_by_seqlen_and_pktlen.mask = selected_pktlen_mask
        selected_mean_acc = np.mean(selected_acc_masked_by_seqlen_and_pktlen)

        selected_sqerr_padded = np.squeeze(selected_sqerr_padded)  # De-batchify the data
        selected_sqerr_masked = np.ma.array(selected_sqerr_padded)
        selected_sqerr_masked[selected_seqlen:] = np.ma.masked

        self.data['predict'] = selected_predict
        self.data['true'] = selected_target
        self.data['acc'] = selected_acc_masked_by_seqlen
        self.data['mean_acc'] = selected_mean_acc
        self.data['squared_error'] = selected_sqerr_masked
        self.data['dim_names'] = self.dim_names
        self.data['pktlen_mask'] = selected_pktlen_mask

        # Load accuracy graph
        self.loadAccuracyGraph(self.data)

    def findPcapFile(self):
        # Search for the pcap file from the directory
        found_pcap_dirs = []
        for pcap_dir in self.pcap_dirs:
            command = 'find '+pcap_dir+' -path '+'*'+self.selected_trafficname
            out = [line.decode('ascii') for line in subprocess.run(command.split(' '), stdout=subprocess.PIPE).stdout.splitlines()]
            found_pcap_dirs.extend(out)
        if len(found_pcap_dirs) > 1:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Alert', 'More than 1 pcap file found:\n'+'\n'.join(found_pcap_dirs))
            print("Warning: Found more than 1 pcap file! Choosing the first")
        elif len(found_pcap_dirs) == 0:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Alert', 'Pcap file cannot be found!')
            print("Error: Pcap file cannot be found!")
            return 0 
        return found_pcap_dirs[0]

    def loadPcapTable(self):
        self.pcapfile_info = []
        # Using tshark to extract information from pcap files
        tempfile = 'temp.csv'
        command = 'tshark -r -o gui.column.format:"No.","%m","Time","%t","Source","%s","Destination","%d","Protocol","%p","Length","%L","Info","%i"'
        command_split = command.split(' ')
        command_split.insert(2, self.selected_pcapfile)
        with open(tempfile, 'w') as out:
            subprocess.run(command_split, stdout=out)
        with open(tempfile) as tmp_f:
            for line in tmp_f.readlines():
                pkt_info = []
                line = line.strip()
                line = re.sub(' +', ' ',line) # To remove all white spaces
                spaces_idx = [i for i,char in enumerate(line) if char==' ']
                pkt_info.append(line[spaces_idx[0]+1:spaces_idx[1]])    # time
                pkt_info.append(line[spaces_idx[1]+1:spaces_idx[2]])    # src
                pkt_info.append(line[spaces_idx[3]+1:spaces_idx[4]])    # dst
                pkt_info.append(line[spaces_idx[4]+1:spaces_idx[5]])    # prot
                pkt_info.append(line[spaces_idx[5]+1:spaces_idx[6]])    # len
                pkt_info.append(line[spaces_idx[6]+1:])                 # info
                self.pcapfile_info.append(pkt_info)

        # Populate the table widget
        nrow = len(self.pcapfile_info)
        ncol = len(self.pcapfile_info[0])
        self.tableWidget.setRowCount(nrow)
        self.tableWidget.setColumnCount(ncol)
        self.tableWidget.setHorizontalHeaderLabels(['Time', 'Src', 'Dst', 'Prot', 'Len', 'Info'])
        for i in range(nrow):
            for j in range(ncol):
                self.tableWidget.setItem(i, j, QtWidgets.QTableWidgetItem(self.pcapfile_info[i][j]))
        self.tableWidget.resizeColumnsToContents()

        os.remove(tempfile)

    def loadAccuracyGraph(self, data):
        self.accGraph.plot(data)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

