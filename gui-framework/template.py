# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'template.ui'
#
# Created by: PyQt5 UI code generator 5.11.2
#
# WARNING! All changes made in this file will be lost!
import os
import json
import pyshark
import subprocess
from PyQt5 import QtCore, QtGui, QtWidgets

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
        self.tableWidget.setGeometry(QtCore.QRect(260, 80, 1261, 621))
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
        self.tempDimGraph = QtWidgets.QLabel(self.centralwidget)
        self.tempDimGraph.setGeometry(QtCore.QRect(260, 710, 1551, 231))
        self.tempDimGraph.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.tempDimGraph.setAlignment(QtCore.Qt.AlignCenter)
        self.tempDimGraph.setObjectName("tempDimGraph")
        
        # TO-DO
        self.tempAccGraph = QtWidgets.QLabel(self.centralwidget)
        self.tempAccGraph.setGeometry(QtCore.QRect(1530, 80, 281, 621))
        self.tempAccGraph.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.tempAccGraph.setAlignment(QtCore.Qt.AlignCenter)
        self.tempAccGraph.setObjectName("tempAccGraph")

        self.verticalScrollBar = QtWidgets.QScrollBar(self.centralwidget)
        self.verticalScrollBar.setGeometry(QtCore.QRect(1510, 80, 16, 621))
        self.verticalScrollBar.setOrientation(QtCore.Qt.Vertical)
        self.verticalScrollBar.setObjectName("verticalScrollBar")

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
        self.chooseTraffic.setItemText(1, _translate("MainWindow", "Normal"))
        self.chooseTraffic.setItemText(2, _translate("MainWindow", "Thc-tls-dos"))
        self.chooseTraffic.setItemText(3, _translate("MainWindow", "Sample"))
        self.searchCriteriaLabel.setText(_translate("MainWindow", "Search Criteria:"))
        self.chooseSearchCriteria.setItemText(0, _translate("MainWindow", "search..."))
        self.chooseSearchCriteria.setItemText(1, _translate("MainWindow", "Low Accuracy (<0.5)"))
        self.chooseSearchCriteria.setItemText(2, _translate("MainWindow", "High Accuracy (>0.8)"))
        self.settingButton.setText(_translate("MainWindow", "Settings"))
        self.searchButton.setText(_translate("MainWindow", "Search"))
        self.tempDimGraph.setText(_translate("MainWindow", "Temp Packet Graph"))
        self.tempAccGraph.setText(_translate("MainWindow", "Temp Packet Graph"))

    def onSearch(self):
        selected_model = str(self.chooseModel.currentText()).lower().replace(" model", "")
        selected_dataset = str(self.chooseTraffic.currentText()).lower()
        for json_dir in self.json_dirs:
            # directory must follow the naming pattern in the UI for this to work
            if selected_model in json_dir and selected_dataset in json_dir:
                self.json_dir = json_dir
        try:
            # Load the json file into mem
            with open(self.json_dir) as f:
                self.data = json.load(f)

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
        self.selected_traffic = item.text()
        self.loadPcapTable()
        self.loadAccuracyGraph()

    def loadPcapTable(self):
        # Search for the pcap file from the directory
        found_pcap_dirs = []
        for pcap_dir in self.pcap_dirs:
            for root, dirs, files in os.walk(pcap_dir):
                for f in files:
                    if f == self.selected_traffic: 
                        found_pcap_dirs.append(os.path.join(root,f))
        if len(found_pcap_dirs) > 1:
            QWidget.QMessageBox.about(self.centralwidget, 'Alert', 'More than 1 pcap file found:\n'+'\n'.join(found_pcap_dirs))
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
                line = line.strip()
                spaces_idx = [i for i,char in enumerate(line) if char==' ']
                pkt_info.append(line[0])                                # no
                pkt_info.append(line[4:12])                             # time
                pkt_info.append(line[spaces_idx[3]+1:spaces_idx[4]])    # src
                pkt_info.append(line[spaces_idx[5]+1:spaces_idx[6]])    # dst
                pkt_info.append(line[spaces_idx[6]+1:spaces_idx[7]])    # prot
                pkt_info.append(line[spaces_idx[7]+1:spaces_idx[8]])    # len
                pkt_info.append(line[spaces_idx[8]+1:])                 # info
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
        self.tableWidget.setHorizontalHeaderLabels(['No.', 'Time', 'Src', 'Dst', 'Prot', 'Len', 'Info'])
        for i in range(nrow):
            for j in range(ncol):
                self.tableWidget.setItem(i, j, QtWidgets.QTableWidgetItem(self.pcapfile_info[i][j]))
        self.tableWidget.resizeColumnsToContents()

        subprocess.run(['rm', tempfile])

    def loadAccuracyGraph(self):

        pass

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

