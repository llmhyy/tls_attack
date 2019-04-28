# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'template.ui'
#
# Created by: PyQt5 UI code generator 5.11.2
#
# WARNING! All changes made in this file will be lost!
import os
import re
import json
import time
import numpy as np
import fnmatch
import pyshark
import subprocess
from keras.models import load_model
from PyQt5 import QtCore, QtGui, QtWidgets
import matplotlib.pyplot as plt
from matplotlib.backends.qt_compat import QtCore, QtWidgets
from matplotlib.backends.backend_qt5agg import (FigureCanvas, NavigationToolbar2QT as NavigationToolbar)
from matplotlib.figure import Figure
from ruamel.yaml import YAML

import sys
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

    def plot(self, event, data):
        self.dim_ax.clear()
        self.dim_ax2.clear()

        predict = data['predict']
        true = data['true']
        sqerr = data['squared_error'][0]
        dim_names = data['dim_names']
        ndim = len(dim_names)
        index = [i for i in range(ndim)]
        packet_num = int(round(event.mouseevent.ydata))-1

        self.dim_ax.bar(index, predict[0,packet_num,:], self.bar_width,
                            alpha=self.opacity, color='b', label='Predict')
        self.dim_ax.bar([i+self.bar_width for i in index], true[0,packet_num,:], self.bar_width,
                            alpha=self.opacity, color='r', label='True')
        self.dim_ax.set_xticks([i+(self.bar_width/2) for i in index])
        self.dim_ax.set_xticklabels(dim_names, rotation='vertical', fontsize=6)
        self.dim_ax.legend(loc='upper left', fontsize=7)
        self.dim_ax.set_ylabel('Predict/True output')

        self.dim_ax2.plot(index, sqerr[packet_num], color='#000000', linewidth=0.7)
        self.dim_ax2.set_ylabel('Sq err')

        self.draw()

# MATPLOTLIB CANVAS WIDGET FOR PLOTTING PACKET ACCURACY
class AccCanvas(FigureCanvas):
    def __init__(self, dimcanvas):
        fig = Figure(figsize=(2.81, 6.21))
        FigureCanvas.__init__(self, fig)
        self.acc_fig = self.figure
        self.acc_ax = self.acc_fig.subplots()
        self.dimcanvas = dimcanvas

    def plot(self, data):
        self.dimcanvas.dim_ax.clear()
        self.dimcanvas.dim_ax2.clear()
        self.dimcanvas.draw()
        self.acc_ax.clear()

        self.data = data
        acc = self.data['acc'][0]
        mean_acc = self.data['mean_acc'][0]
        self.acc_ax.plot(acc, [i+1 for i in range(len(acc))])
        for i,pkt_acc in enumerate(acc):
            self.acc_ax.plot(pkt_acc, i+1, 'ro', picker=5)
            self.acc_ax.text((pkt_acc-0.05), i+1, i+1, fontsize=8, horizontalalignment='center')
        self.acc_ax.invert_yaxis()
        self.acc_ax.set_title('Mean Acc: {}'.format(mean_acc))
        self.acc_ax.set_xlabel('Acc')
        self.acc_fig.canvas.mpl_connect('pick_event', self.on_pick)
        self.draw()

    def on_pick(self, event):
        self.dimcanvas.plot(event, self.data)

class Ui_MainWindow(object):
    def __init__(self, pcap_dirs, model_dirs, feature_dirs):
        self.pcap_dirs = pcap_dirs
        self.model_dirs = model_dirs
        self.feature_dirs = feature_dirs

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1838, 963)
        MainWindow.setStyleSheet("background-color: rgb(74, 136, 204);")
        
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        self.background = QtWidgets.QLabel(self.centralwidget)
        self.background.setStyleSheet("background-color: rgb(212, 217, 217);")
        self.background.setText("")
        self.background.setObjectName("background")
        
        self.vbox1 = QtWidgets.QVBoxLayout()
        self.vbox1.addWidget(self.background)
        self.centralwidget.setLayout(self.vbox1)

        self.chooseModel = QtWidgets.QComboBox()
        self.chooseModel.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.chooseModel.setEditable(False)
        self.chooseModel.setObjectName("chooseModel")
        self.chooseModel.addItem("- Model type -")
        for m in config.model.keys():
            self.chooseModel.addItem('{} model'.format(m.title()))
        # self.chooseModel.addItem("Normal model")
        # self.chooseModel.addItem("Thc-tls-dos model")
        # self.chooseModel.addItem("Sample model")

        self.predictsOnLabel = QtWidgets.QLabel()
        self.predictsOnLabel.setStyleSheet("background-color: rgb(212, 217, 217);")
        self.predictsOnLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.predictsOnLabel.setObjectName("predictsOnLabel")
        self.predictsOnLabel.setText('predicts on')
        
        self.chooseTraffic = QtWidgets.QComboBox()
        self.chooseTraffic.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.chooseTraffic.setObjectName("chooseTraffic")
        self.chooseTraffic.addItem("- Traffic type -")
        for f in config.features.keys():
            self.chooseTraffic.addItem('{} (train)'.format(f.title()))
            self.chooseTraffic.addItem('{} (val)'.format(f.title()))
        # self.chooseTraffic.addItem("Normal (train)")
        # self.chooseTraffic.addItem("Normal (val)")
        # self.chooseTraffic.addItem("Thc-tls-dos (train)")
        # self.chooseTraffic.addItem("Thc-tls-dos (val)")
        # self.chooseTraffic.addItem("Sample (train)")
        # self.chooseTraffic.addItem("Sample (val)")

        self.searchCriteriaLabel = QtWidgets.QLabel()
        self.searchCriteriaLabel.setStyleSheet("background-color: rgb(212, 217, 217);")
        self.searchCriteriaLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.searchCriteriaLabel.setObjectName("searchCriteriaLabel")
        
        self.chooseSearchCriteria = QtWidgets.QComboBox()
        self.chooseSearchCriteria.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.chooseSearchCriteria.setObjectName("chooseSearchCriteria")
        self.chooseSearchCriteria.addItem("search...")
        self.chooseSearchCriteria.addItem("Low Accuracy (<0.5)")
        self.chooseSearchCriteria.addItem("High Accuracy (>0.8)")

        self.searchButton = QtWidgets.QPushButton()
        self.searchButton.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.searchButton.setObjectName("searchButton")
        self.searchButton.setText('Search')
        self.searchButton.clicked.connect(self.onSearch)
        
        self.settingButton = QtWidgets.QPushButton()
        self.settingButton.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.settingButton.setObjectName("settingButton")
        self.settingButton.setText('Settings')

        self.hbox1 = QtWidgets.QHBoxLayout()
        self.hbox1.addWidget(self.chooseModel)
        self.hbox1.addWidget(self.predictsOnLabel)
        self.hbox1.addWidget(self.chooseTraffic)
        self.hbox1.addStretch(1)
        self.hbox1.addWidget(self.searchCriteriaLabel)
        self.hbox1.addWidget(self.chooseSearchCriteria)
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
        self.listWidget.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.listWidget.setObjectName("listWidget")

        self.vbox3 = QtWidgets.QVBoxLayout()
        self.vbox3.addWidget(self.trafficLabel)
        self.vbox3.addWidget(self.listWidget)
        self.vbox3.setSpacing(0)
        
        self.dimGraph = DimCanvas()
        self.dimGraphWidget = PlotWidget()
        self.dimGraphWidget.add_canvas(self.dimGraph)
        self.dimGraph.setParent(self.dimGraphWidget)

        self.tableWidget = QtWidgets.QTableWidget()
        self.tableWidget.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.tableWidget.setShowGrid(True)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(0)
        self.tableWidget.setRowCount(0)
        self.tableWidget.verticalHeader().setVisible(True)
        
        self.accGraph = AccCanvas(self.dimGraph)
        self.accGraphWidget = PlotWidget()
        self.accGraphWidget.add_canvas(self.accGraph)
        self.accGraph.setParent(self.accGraphWidget)

        self.hbox3 = QtWidgets.QHBoxLayout()
        self.hbox3.addWidget(self.tableWidget, 6.5)
        self.hbox3.addWidget(self.accGraphWidget, 3.5)

        self.vbox4 = QtWidgets.QVBoxLayout()
        self.vbox4.addLayout(self.hbox3, 6)
        self.vbox4.addWidget(self.dimGraphWidget, 4)

        self.hbox2 = QtWidgets.QHBoxLayout()
        self.hbox2.addLayout(self.vbox3, 1.75)
        self.hbox2.addLayout(self.vbox4, 8.25)
        
        self.vbox2 = QtWidgets.QVBoxLayout()
        self.vbox2.addLayout(self.hbox1, 1)
        self.vbox2.addLayout(self.hbox2, 9)
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
        model_name = str(self.chooseModel.currentText()).lower().replace(" model", "")
        tmp_path = os.path.join(self.model_dirs, config.model[model_name])
        if not os.path.exists(tmp_path):
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Model not found. Check config.py')
            return
        self.model = load_model(tmp_path)

        SPLIT_RATIO = 0.05
        SEED = 2019
        SEQUENCE_LEN = 100
        FEATURE_FILENAME = 'features_tls_*.csv'
        FEATUREINFO_FILENAME = 'feature_info_*.csv'
        PCAPNAME_FILENAME = 'pcapname_*.csv'
        
        tmp = str(self.chooseTraffic.currentText()).lower().split('(')
        dataset_name = tmp[0].strip()
        split_name = tmp[1].rstrip(')')
        tmp_path = os.path.join(self.feature_dirs,config.features[dataset_name])
        if not os.path.exists(tmp_path):
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Feature directory not found. Check config.py')
            return
        self.feature_dir = tmp_path
        filenames = os.listdir(self.feature_dir)

        # Load the train/test indexes from split
        self.featurecsv_dir = os.path.join(self.feature_dir, fnmatch.filter(filenames, FEATURE_FILENAME)[0])
        # Get the number of lines in a file to determine split
        with open(self.featurecsv_dir) as f:
            for i, line in enumerate(f):
                pass
            line_count = i+1
        train_idx, test_idx = utilsDatagen.split_train_test(range(line_count), SPLIT_RATIO, SEED)
        print('line count: {}'.format(line_count))
        print('train idx: {}'.format(len(train_idx)))
        print('test idx: {}'.format(len(test_idx)))
        if split_name == 'train':
            dataset_idx = train_idx
        elif split_name == 'val':
            dataset_idx = test_idx

        # Load the pcap filenames from train/test indexes
        self.pcapname_dir = os.path.join(self.feature_dir, fnmatch.filter(filenames, PCAPNAME_FILENAME)[0])
        with open(self.pcapname_dir) as f:
            lines = f.readlines()
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

        # Load the traffic into ListWidget
        try:
            self.loadTraffic(dataset_name)
        except AttributeError as e:
            print(e)

    def loadTraffic(self, dataset_name):
        tmp_path = os.path.join(self.pcap_dirs, config.pcapfiles[dataset_name])
        if not os.path.exists(tmp_path):
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Pcap directory not found. Check config.py')
            return
        pcap_dir = tmp_path
        count = 0
        # Get the dataset from the pcap directory and add to ListWidget
        normalized_pcap_filenames = [os.path.normcase(i) for i in self.pcap_filenames]
        start = time.time()
        pcap_dir_files = []
        for root,dirs,files in os.walk(pcap_dir):
            for f in files:
                if f.endswith('.pcap'):
                    pcap_dir_files.append(os.path.join(root,f))
        sorted_pcap_dir_files = sorted(pcap_dir_files)
        sorted_normalized_pcap_filenames = sorted(normalized_pcap_filenames)
        pointer = 0
        for pf in sorted_pcap_dir_files:
            # print('Searching for {}'.format(pf))
            for i in range(pointer, len(sorted_normalized_pcap_filenames)):
                # print('Trying {}'.format(sorted_normalized_pcap_filenames[i]))
                if sorted_normalized_pcap_filenames[i] in pf:
                    self.listWidget.addItem(pf)
                    pointer = i+1
                    count+=1
                    break
        print('Time taken to search: {}'.format(time.time()-start))
        print('{} traffic loaded into ListWidget'.format(count))
        self.listWidget.itemClicked.connect(self.onClickTraffic)

    def onClickTraffic(self, item):
        # Load pcap table
        # self.selected_trafficname = item.text()
        # self.selected_trafficidx = self.pcap_filename2idx[self.selected_trafficname]
        # self.selected_pcapfile = self.findPcapFile()
        self.selected_pcapfile = item.text()
        if self.selected_pcapfile == 0:
            return
        self.loadPcapTable()
        
        # Generate features from PCAP file
        ENUMS_FILENAME = 'enums_ref.yml'
        with open(os.path.join(self.feature_dirs, '..', ENUMS_FILENAME)) as f:
            enums = yaml.load(f)
        try:
            tcp_features = utilsFeatureExtract.extract_tcp_features(self.selected_pcapfile, limit=200)
            tls_features = utilsFeatureExtract.extract_tslssl_features(self.selected_pcapfile, enums, limit=200)
        except (KeyError, AttributeError, TypeError):
            QtWidgets.QMessageBox.about(self.centralwidget, 'Error', 'Feature extraction failed. Choose another traffic')
            return
        traffic_features = np.concatenate((np.array(tcp_features), np.array(tls_features)), axis=1)
        traffic_features = traffic_features.reshape(1, *traffic_features.shape)     # Batchify the traffic features
        
        # Preprocess the features
        SEQUENCE_LEN = 100
        MINMAX_FILENAME = 'minmax_features.csv'
        try:
            with open(os.path.join(self.feature_dir, MINMAX_FILENAME), 'r') as f:
                min_max_feature_list = json.load(f)
            min_max_feature = (np.array(min_max_feature_list[0]), np.array(min_max_feature_list[1]))
        except FileNotFoundError:
            print('Error: min-max feature file cannot be found in the extracted-features directory of the selected database')
        norm_fn = utilsDatagen.normalize(2, min_max_feature)
        selected_seq_len = [len(traffic_features[0])]
        selected_input, selected_target = utilsDatagen.preprocess_data(traffic_features, pad_len=SEQUENCE_LEN, norm_fn=norm_fn)

        # Compute metrics for GUI 
        data = {}
        selected_predict = self.model.predict_on_batch(selected_input)
        selected_acc_padded = utilsMetric.calculate_acc_of_traffic(selected_predict, selected_target)
        selected_acc_true = [selected_acc_padded[i,0:seq_len] for i,seq_len in enumerate(selected_seq_len)]
        selected_mean_acc = [np.mean(acc) for acc in selected_acc_true]
        selected_sqerr_padded = utilsMetric.calculate_squared_error_of_traffic(selected_predict, selected_target)
        selected_sqerr_true = [selected_sqerr_padded[i,0:seq_len,:] for i,seq_len in enumerate(selected_seq_len)]
        data['predict'] = selected_predict
        data['true'] = selected_target
        data['acc'] = selected_acc_true
        data['mean_acc'] = selected_mean_acc
        data['squared_error'] = selected_sqerr_true
        data['dim_names'] = self.dim_names

        # Load accuracy graph
        self.loadAccuracyGraph(data)

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
        command = 'tshark -r '+self.selected_pcapfile+' -o gui.column.format:"No.","%m","Time","%t","Source","%s","Destination","%d","Protocol","%p","Length","%L","Info","%i"'
        with open(tempfile, 'w') as out:
            subprocess.run(command.split(' '), stdout=out)
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

        subprocess.run(['rm', tempfile])

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

