# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'template.ui'
#
# Created by: PyQt5 UI code generator 5.11.2
#
# WARNING! All changes made in this file will be lost!
import os
import re
import json
import numpy as np
import pyshark
import subprocess
from PyQt5 import QtCore, QtGui, QtWidgets

import matplotlib.pyplot as plt
from matplotlib.backends.qt_compat import QtCore, QtWidgets
from matplotlib.backends.backend_qt5agg import (FigureCanvas, NavigationToolbar2QT as NavigationToolbar)
from matplotlib.figure import Figure
# from matplotlib.transforms import Affine2D
# import mpl_toolkits.axisartist.floating_axes as floating_axes

class Ui_MainWindow(object):
    def __init__(self, json_dirs, pcap_dirs):
        self.json_dirs = json_dirs
        self.pcap_dirs = pcap_dirs

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1838, 963)
        MainWindow.setStyleSheet("background-color: rgb(74, 136, 204);")
        
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        # self.scrollArea = QtWidgets.QScrollArea(self.centralwidget)
        # self.scrollArea.setGeometry(QtCore.QRect(0, 0, 1811, 941))
        # self.scrollArea.setFixedWidth(1000)
        # self.scrollArea.setFixedHeight(500)
        # self.scrollArea.setWidgetResizable(True)
        # self.scrollArea.setObjectName("scrollArea")
        # self.scrollAreaWidgetContents = QtWidgets.QWidget()
        # self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 1811, 941))
        # self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        
        self.background = QtWidgets.QLabel(self.centralwidget)
        self.background.setGeometry(QtCore.QRect(10, 10, 1811, 941))
        self.background.setStyleSheet("background-color: rgb(212, 217, 217);")
        self.background.setText("")
        self.background.setObjectName("background")
        
        self.trafficLabel = QtWidgets.QLabel(self.centralwidget)
        self.trafficLabel.setGeometry(QtCore.QRect(20, 80, 231, 31))
        self.trafficLabel.setStyleSheet("background-color: rgb(90, 145, 205);\ncolor: rgb(255, 255, 255);")
        self.trafficLabel.setTextFormat(QtCore.Qt.PlainText)
        self.trafficLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.trafficLabel.setWordWrap(True)
        self.trafficLabel.setObjectName("trafficLabel")
        
        self.listWidget = QtWidgets.QListWidget(self.centralwidget)
        self.listWidget.setGeometry(QtCore.QRect(20, 110, 231, 831))
        self.listWidget.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.listWidget.setObjectName("listWidget")
        
        self.tableWidget = QtWidgets.QTableWidget(self.centralwidget)
        # self.tableWidget.setGeometry(QtCore.QRect(260, 80, 1261, 621))
        self.tableWidget.setGeometry(QtCore.QRect(260, 80, 1171, 560))
        self.tableWidget.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.tableWidget.setShowGrid(True)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(0)
        self.tableWidget.setRowCount(0)
        self.tableWidget.verticalHeader().setVisible(True)
        
        self.chooseModel = QtWidgets.QComboBox(self.centralwidget)
        self.chooseModel.setGeometry(QtCore.QRect(20, 40, 281, 31))
        self.chooseModel.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.chooseModel.setEditable(False)
        self.chooseModel.setObjectName("chooseModel")
        self.chooseModel.addItem("")
        self.chooseModel.addItem("")
        self.chooseModel.addItem("")
        self.chooseModel.addItem("")
        
        self.predictsOnLabel = QtWidgets.QLabel(self.centralwidget)
        self.predictsOnLabel.setGeometry(QtCore.QRect(300, 40, 91, 31))
        self.predictsOnLabel.setStyleSheet("background-color: rgb(212, 217, 217);")
        self.predictsOnLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.predictsOnLabel.setObjectName("predictsOnLabel")
        
        self.chooseTraffic = QtWidgets.QComboBox(self.centralwidget)
        self.chooseTraffic.setGeometry(QtCore.QRect(390, 40, 261, 31))
        self.chooseTraffic.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.chooseTraffic.setObjectName("chooseTraffic")
        self.chooseTraffic.addItem("")
        self.chooseTraffic.addItem("")
        self.chooseTraffic.addItem("")
        self.chooseTraffic.addItem("")
        self.chooseTraffic.addItem("")
        self.chooseTraffic.addItem("")
        self.chooseTraffic.addItem("")
        
        self.searchCriteriaLabel = QtWidgets.QLabel(self.centralwidget)
        self.searchCriteriaLabel.setGeometry(QtCore.QRect(1050, 40, 111, 31))
        self.searchCriteriaLabel.setStyleSheet("background-color: rgb(212, 217, 217);")
        self.searchCriteriaLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.searchCriteriaLabel.setObjectName("searchCriteriaLabel")
        
        self.chooseSearchCriteria = QtWidgets.QComboBox(self.centralwidget)
        self.chooseSearchCriteria.setGeometry(QtCore.QRect(1160, 40, 261, 31))
        self.chooseSearchCriteria.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.chooseSearchCriteria.setObjectName("chooseSearchCriteria")
        self.chooseSearchCriteria.addItem("")
        self.chooseSearchCriteria.addItem("")
        self.chooseSearchCriteria.addItem("")
        
        self.settingButton = QtWidgets.QPushButton(self.centralwidget)
        self.settingButton.setGeometry(QtCore.QRect(1630, 40, 181, 31))
        self.settingButton.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.settingButton.setObjectName("settingButton")
        
        self.searchButton = QtWidgets.QPushButton(self.centralwidget)
        self.searchButton.setGeometry(QtCore.QRect(1438, 40, 181, 31))
        self.searchButton.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.searchButton.setObjectName("searchButton")
        self.searchButton.clicked.connect(self.onSearch)
        
        # TO-DO
        # self.tempDimGraph = QtWidgets.QLabel(self.centralwidget)
        # self.tempDimGraph.setGeometry(QtCore.QRect(260, 710, 1551, 231))
        # self.tempDimGraph.setStyleSheet("background-color: rgb(255, 255, 255);")
        # self.tempDimGraph.setAlignment(QtCore.Qt.AlignCenter)
        # self.tempDimGraph.setObjectName("tempDimGraph")
        self.dimGraph = FigureCanvas(Figure(figsize=(15.51, 2.31)))
        # self.dimGraph.setGeometry(QtCore.QRect(260, 710, 1551, 231))
        self.dimGraph.setGeometry(QtCore.QRect(260, 649, 1551, 292))
        self.dimGraph.setParent(self.centralwidget)
        self.dim_fig = self.dimGraph.figure
        # self.dim_fig.tight_layout()
        self.dim_fig.subplots_adjust(bottom=0.5, left=0.05, right=0.95)
        self.dim_ax = self.dim_fig.subplots()
        self.dim_ax2 = self.dim_ax.twinx()

        # TO-DO
        # self.tempAccGraph = QtWidgets.QLabel(self.centralwidget)
        # self.tempAccGraph.setGeometry(QtCore.QRect(1530, 80, 281, 621))
        # self.tempAccGraph.setStyleSheet("background-color: rgb(255, 255, 255);")
        # self.tempAccGraph.setAlignment(QtCore.Qt.AlignCenter)
        # self.tempAccGraph.setObjectName("tempAccGraph")
        self.accGraph = FigureCanvas(Figure(figsize=(2.81, 6.21)))
        # self.accGraph.setGeometry(QtCore.QRect(1530, 80, 281, 560))
        self.accGraph.setGeometry(QtCore.QRect(1440, 80, 371, 560))
        self.accGraph.setParent(self.centralwidget)
        self.acc_fig = self.accGraph.figure
        self.acc_ax = self.acc_fig.subplots()

        # self.verticalScrollBar = QtWidgets.QScrollBar(self.centralwidget)
        # self.verticalScrollBar.setGeometry(QtCore.QRect(1510, 80, 16, 560))
        # self.verticalScrollBar.setOrientation(QtCore.Qt.Vertical)
        # self.verticalScrollBar.setObjectName("verticalScrollBar")

        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.trafficLabel.setText(_translate("MainWindow", "Traffic"))
        self.chooseModel.setItemText(0, _translate("MainWindow", "- Model type -"))
        self.chooseModel.setItemText(1, _translate("MainWindow", "Normal model"))
        self.chooseModel.setItemText(2, _translate("MainWindow", "Thc-tls-dos model"))
        self.chooseModel.setItemText(3, _translate("MainWindow", "Sample model"))
        self.predictsOnLabel.setText(_translate("MainWindow", "predicts on"))
        self.chooseTraffic.setItemText(0, _translate("MainWindow", "- Traffic type -"))
        self.chooseTraffic.setItemText(1, _translate("MainWindow", "Normal (train)"))
        self.chooseTraffic.setItemText(2, _translate("MainWindow", "Normal (val)"))
        self.chooseTraffic.setItemText(3, _translate("MainWindow", "Thc-tls-dos (train)"))
        self.chooseTraffic.setItemText(4, _translate("MainWindow", "Thc-tls-dos (val)"))
        self.chooseTraffic.setItemText(5, _translate("MainWindow", "Sample (train)"))
        self.chooseTraffic.setItemText(6, _translate("MainWindow", "Sample (val)"))
        self.searchCriteriaLabel.setText(_translate("MainWindow", "Search Criteria:"))
        self.chooseSearchCriteria.setItemText(0, _translate("MainWindow", "search..."))
        self.chooseSearchCriteria.setItemText(1, _translate("MainWindow", "Low Accuracy (<0.5)"))
        self.chooseSearchCriteria.setItemText(2, _translate("MainWindow", "High Accuracy (>0.8)"))
        self.settingButton.setText(_translate("MainWindow", "Settings"))
        self.searchButton.setText(_translate("MainWindow", "Search"))
        # self.tempDimGraph.setText(_translate("MainWindow", "Temp Packet Graph"))
        # self.tempAccGraph.setText(_translate("MainWindow", "Temp Packet Graph"))

    def onSearch(self):
        selected_model = str(self.chooseModel.currentText()).lower().replace(" model", "")
        tmp = str(self.chooseTraffic.currentText()).lower().split('(')
        selected_dataset = tmp[0].strip()
        selected_split = tmp[1].rstrip(')')
        for json_dir in self.json_dirs:
            json_dir_list = json_dir.split(os.sep)
            # directory must follow the naming pattern in the UI for this to work
            if selected_model in json_dir_list[-6] and selected_dataset in json_dir_list[-3] and selected_split in json_dir_list[-2]:
                self.json_dir = json_dir
        try:
            # Load the json file into mem
            with open(self.json_dir) as f:
                self.data = json.load(f)
                self.predict_for_all_traffic = np.array(self.data['predict'])
                self.true_for_all_traffic = np.array(self.data['true'])

            # Load the traffic into ListWidget
            self.loadTraffic()
        except AttributeError:
            print("Error: Directory to json file cannot be found. Please choose another option")

    def loadTraffic(self):
        # Get and filter through criteria
        criteria = self.chooseSearchCriteria.currentText()
        # TODO

        pcap_filenames = self.data['pcap_filenames']
        for pcap_filename in pcap_filenames:
            self.listWidget.addItem(pcap_filename)
        self.listWidget.itemClicked.connect(self.onClickTraffic)

    def onClickTraffic(self, item):
        print(item.text())
        self.selected_trafficname = item.text()
        self.selected_trafficidx = self.data['pcap_filenames'].index(self.selected_trafficname)
        print(len(self.data['pcap_filenames']))
        print(self.selected_trafficidx)
        print(len(self.data['idx']))
        # self.selected_trafficidx = self.data['idx'].index(orig_idx)
        self.loadPcapTable()
        self.loadAccuracyGraph()

    def loadPcapTable(self):
        # Search for the pcap file from the directory
        found_pcap_dirs = []
        for pcap_dir in self.pcap_dirs:
            for root, dirs, files in os.walk(pcap_dir):
                for f in files:
                    if f == self.selected_trafficname: 
                        found_pcap_dirs.append(os.path.join(root,f))
        if len(found_pcap_dirs) > 1:
            QtWidgets.QMessageBox.about(self.centralwidget, 'Alert', 'More than 1 pcap file found:\n'+'\n'.join(found_pcap_dirs))
            print("Found more than 1 pcap file!")
        self.selected_pcapfile = found_pcap_dirs[0]

        # Extract details from pcap file
        # self.pcapfile_info = {}
        # self.pcapfile_info['no'] = []
        # self.pcapfile_info['time'] = []
        # self.pcapfile_info['src'] = []
        # self.pcapfile_info['dst'] = []
        # self.pcapfile_info['prot'] = []
        # self.pcapfile_info['len'] = []
        # self.pcapfile_info['info'] = []

        self.pcapfile_info = []

        ### -- Using tshark -- ###
        tempfile = 'temp.csv'
        command = 'tshark -r '+self.selected_pcapfile+' -o gui.column.format:"No.","%m","Time","%t","Source","%s","Destination","%d","Protocol","%p","Length","%L","Info","%i"'
        with open(tempfile, 'w') as out:
            subprocess.run(command.split(' '), stdout=out)
        with open(tempfile) as tmp_f:
            for line in tmp_f.readlines():
                pkt_info = []
                print(line)
                line = line.strip()
                line = re.sub(' +', ' ',line) # To remove all white spaces
                spaces_idx = [i for i,char in enumerate(line) if char==' ']
                # pkt_info.append(line[0])                                # no
                pkt_info.append(line[spaces_idx[0]+1:spaces_idx[1]])    # time
                pkt_info.append(line[spaces_idx[1]+1:spaces_idx[2]])    # src
                pkt_info.append(line[spaces_idx[3]+1:spaces_idx[4]])    # dst
                pkt_info.append(line[spaces_idx[4]+1:spaces_idx[5]])    # prot
                pkt_info.append(line[spaces_idx[5]+1:spaces_idx[6]])    # len
                pkt_info.append(line[spaces_idx[6]+1:])                 # info
                self.pcapfile_info.append(pkt_info)

        ### -- Using Pyshark -- ###
        # packets = pyshark.FileCapture(self.selected_pcapfile)
        # for i,packet in enumerate(packets):
        #     print(packet)
        #     self.pcapfile_info['time'].append(float(packet.frame_info.time_relative))
        #     self.pcapfile_info['src'].append(str(packet.ip.src))
        #     self.pcapfile_info['dst'].append(str(packet.ip.dst))
        #     self.pcapfile_info['prot'].append(str(packet.highest_layer))
        #     self.pcapfile_info['len'].append(int(packet.length))
        #     self.pcapfile_info[]

        # Populate the table widget
        nrow = len(self.pcapfile_info)
        ncol = len(self.pcapfile_info[0])
        self.tableWidget.setRowCount(nrow)
        self.tableWidget.setColumnCount(ncol)
        # self.tableWidget.setHorizontalHeaderLabels(['No.', 'Time', 'Src', 'Dst', 'Prot', 'Len', 'Info'])
        self.tableWidget.setHorizontalHeaderLabels(['Time', 'Src', 'Dst', 'Prot', 'Len', 'Info'])
        for i in range(nrow):
            for j in range(ncol):
                self.tableWidget.setItem(i, j, QtWidgets.QTableWidgetItem(self.pcapfile_info[i][j]))
        self.tableWidget.resizeColumnsToContents()

        subprocess.run(['rm', tempfile])

    def loadAccuracyGraph(self):
        self.acc_ax.clear()
        # self.acc_fig.clf()

        def on_pick(event):
            # print(event)
            print(round(event.mouseevent.xdata))
            print(round(event.mouseevent.ydata))

            self.dim_ax.clear()
            self.dim_ax2.clear()
            ndim = len(self.data['dim_names'])
            index = [i for i in range(ndim)]
            bar_width = 0.3
            opacity = 0.5
            packet_num = int(round(event.mouseevent.ydata))-1
            # print(packet_num)
            predict_for_all_traffic = self.data['predict']

            # print(self.predict_for_all_traffic[self.selected_trafficidx,packet_num,:])
            self.dim_ax.bar(index, self.predict_for_all_traffic[self.selected_trafficidx,packet_num,:], bar_width,
                                alpha=opacity, color='b', label='Predict')
            self.dim_ax.bar([i+bar_width for i in index], self.true_for_all_traffic[self.selected_trafficidx,packet_num,:], bar_width,
                                alpha=opacity, color='r', label='True')
            self.dim_ax.set_xticks([i+(bar_width/2) for i in index])
            self.dim_ax.set_xticklabels(self.data['dim_names'], rotation='vertical', fontsize=6)
            self.dim_ax.legend(loc='upper left', fontsize=7)
            self.dim_ax.set_ylabel('Predict/True output')
            self.dim_ax2.set_ylabel('Sq Err')

            # print(self.data['squared_error'][self.selected_trafficidx][packet_num])
            self.dim_ax2.plot(index, self.data['squared_error'][self.selected_trafficidx][packet_num], color='#000000', linewidth=0.7)

            self.dimGraph.draw()

        selected_pktwise_acc = self.data['acc'][self.selected_trafficidx]
        # self.acc_fig.suptitle('Mean Acc: {}'.format(self.data['mean_acc'][self.selected_trafficidx]))
        self.acc_ax.plot(selected_pktwise_acc, [i+1 for i in range(len(selected_pktwise_acc))])
        for i, pkt_acc in enumerate(selected_pktwise_acc):
            self.acc_ax.plot(pkt_acc, i+1, 'ro', picker=5)
            self.acc_ax.text((pkt_acc-0.05), i+1, i+1, fontsize=9, horizontalalignment='center')
        self.acc_ax.invert_yaxis()
        self.acc_ax.set_title('Mean Acc: {}'.format(self.data['mean_acc'][self.selected_trafficidx]))
        self.acc_ax.set_ylabel('# packets')
        self.acc_ax.set_xlabel('Acc')
        try:
            self.dim_ax.clear()
            self.dim_ax2.clear()
        except AttributeError:
            print("Warning: Dim axes does not exist")

        self.acc_fig.canvas.mpl_connect('pick_event', on_pick)

        # t = np.linspace(0, 10, 501)
        # self.acc_ax.plot(t, np.tan(t), ".")
        self.accGraph.draw()
        print("plotted!")

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

