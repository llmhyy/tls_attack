from PyQt5 import QtCore, QtGui, QtWidgets

lst = [u"D", u"E", u"EF", u"F", u"FG", u"G", u"H", u"JS", u"J", u"K", u"M", u"P", u"R", u"S", u"T", u"U", u"V", u"X", u"Y", u"Z"]

class MyApp(QtWidgets.QWidget):
    def __init__(self):
        super(MyApp, self).__init__()
        window_width = 1200
        window_height = 600
        self.setFixedSize(window_width, window_height)
        self.initUI()

    def createLayout_group(self, number):
        sgroupbox = QtWidgets.QGroupBox("Group{}:".format(number), self)
        layout_groupbox = QtWidgets.QVBoxLayout(sgroupbox)
        for i in range(len(lst)):
            item = QtWidgets.QCheckBox(lst[i], sgroupbox)
            layout_groupbox.addWidget(item)
        layout_groupbox.addStretch(1)
        return sgroupbox

    def createLayout_Container(self):
        self.scrollarea = QtWidgets.QScrollArea(self)
        self.scrollarea.setFixedWidth(250)
        self.scrollarea.setWidgetResizable(True)

        widget = QtWidgets.QWidget()
        self.scrollarea.setWidget(widget)
        self.layout_SArea = QtWidgets.QVBoxLayout(widget)

        for i in range(5):
            self.layout_SArea.addWidget(self.createLayout_group(i))
        self.layout_SArea.addStretch(1)

    def initUI(self):
        self.createLayout_Container()
        self.layout_All = QtWidgets.QVBoxLayout(self)
        self.layout_All.addWidget(self.scrollarea)
        self.show()

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    # MainWindow = QtWidgets.QMainWindow()
    ui = MyApp()
    # MainWindow.show()
    sys.exit(app.exec_())