import os
import sys
import argparse
from template import Ui_MainWindow
from PyQt5 import QtCore, QtGui, QtWidgets

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--rootdir', help='Input the root directory path containing the data in json format for all trained model. Typically, foo/bar/trained-rnn/', required=True)
parser.add_argument('-p', '--pcapdir', nargs='+', help='Input all directories to where pcap files are located', required=True)
args = parser.parse_args()

# Search iteratively for all data.json files in the root directory
json_dirs = []
for root, dirs, files in os.walk(args.rootdir):
	for f in files:
		if f == "data.json":
			json_dirs.append(os.path.join(root, f))

pcap_dirs = args.pcapdir

app = QtWidgets.QApplication(sys.argv)
# app.resize(1838, 963)
MainWindow = QtWidgets.QMainWindow()
ui = Ui_MainWindow(json_dirs, pcap_dirs)
ui.setupUi(MainWindow)

MainWindow.show()
sys.exit(app.exec_())