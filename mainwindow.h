#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtGui>

#include "whoisinfo.h"

class mainWindow : public QWidget
{
	Q_OBJECT

private:
	QBoxLayout *lay_main;
	QBoxLayout *lay_top;
	QLabel *lbl_input;
	QLineEdit *edt_input;
	QPushButton *btn_input;
	QTextEdit *edt_output;
	QSplitter *split1;
	QLabel *lbl_stat;

	QAction *a_toggleHtmlView;

	QMenuBar *menu;
		QMenu *fileMenu;
		QMenu *editMenu;

	QStatusBar *statusbar;

	WhoisInfo *whois;

	void setupActions();
	void setupMenus();

public:
	mainWindow(void);

protected:


public slots:
	void getData(QString server="whois.arin.net");
	void saveData();
	void copyData();
	void selectAllData();
};

mainWindow::mainWindow()
{
	this->setWindowTitle("WhoDat");

	lay_main = new QBoxLayout(QBoxLayout::TopToBottom, this);
	lay_main->setMargin(6);
	lay_main->setSpacing(0);
	//lay_main->setContentsMargins();

	setupMenus();

	lay_top = new QBoxLayout(QBoxLayout::LeftToRight);
	lay_top->setSpacing(4);

	lbl_input = new QLabel();
	lbl_input->setText("Address");
	lay_top->addWidget(lbl_input);

	edt_input = new QLineEdit();
	lay_top->addWidget(edt_input, 1);

	btn_input = new QPushButton();
	btn_input->setText(" Search");
	btn_input->setIcon(QIcon(":/resources/images/ico_search.png"));
	lay_top->addWidget(btn_input);

	lay_main->addLayout(lay_top);

	edt_output = new QTextEdit();
	edt_output->setWordWrapMode(QTextOption::NoWrap);
	edt_output->setReadOnly(true);
	edt_output->setAcceptRichText(false);
	lay_main->addWidget(edt_output, 1);

	statusbar = new QStatusBar(this);
	lbl_stat = new QLabel("");
	statusbar->addWidget(lbl_stat, 1);

	lay_main->addWidget(statusbar);

	this->resize(600, 300);

	whois = new WhoisInfo(statusbar);

	QObject::connect(btn_input, SIGNAL(clicked()), this, SLOT(getData()));
	QObject::connect(edt_input, SIGNAL(returnPressed()), this, SLOT(getData()));
}

void mainWindow::setupMenus()
{
	fileMenu = new QMenu();
	fileMenu->setTitle("File");
	fileMenu->addAction("Save", this, SLOT(saveData()), QKeySequence::Save);
	fileMenu->addAction("Quit", qApp, SLOT(quit()),QKeySequence::Quit);

	editMenu = new QMenu();
	editMenu->setTitle("Edit");
	editMenu->addAction("Copy", this, SLOT(copyData()), QKeySequence::Copy);
	editMenu->addAction("Select All", this, SLOT(selectAllData()), QKeySequence::SelectAll);

	menu = new QMenuBar();
	menu->setMinimumHeight(22);
	menu->addMenu(fileMenu);
	menu->addMenu(editMenu);

	this->lay_main->setMenuBar(menu);

}

void mainWindow::getData(QString server)
{
	whois->query(this->edt_input->text());
	this->edt_output->setText(whois->outputPlainText());
	this->edt_output->setFocus();
}

void mainWindow::saveData()
{
	QFileDialog dlg;
	QString filename;

	QString txt = whois->outputPlainText();

	if(!txt.isEmpty())
	{
		QString default_filename = whois->LastQuery.replace(".", "-")+".txt";

		dlg.setDirectory(QDesktopServices::storageLocation(QDesktopServices::DesktopLocation));

		qDebug() << QDesktopServices::storageLocation(QDesktopServices::DesktopLocation);

		// Hmmm.. Why is there no setFilename method? Seems like a no brainer.

		filename = dlg.getSaveFileName(this, "Save Whois Information", "", "Text File (*.txt);");
		if(filename != "")
		{
			QFile file(filename);
			if(file.open(QIODevice::WriteOnly | QIODevice::Text))
			{
				file.write( txt.toLatin1() );
				file.close();
			}
			else
			{
				QMessageBox::information(this, "error", "Couldn't write to file.");
			}
		}
	}

}

void mainWindow::copyData()
{
	QClipboard *clip;

	clip = QApplication::clipboard();

	if(this->edt_output->textCursor().hasSelection())
	{
		// From qtextcontrol.cpp:855
		// But it's protected so can't use it... right?
		//QMimeData *data = this->edt_output->createMimeDataFromSelection();
		//clip->setMimeData(data);

		this->edt_output->copy(); // Also works.
	}
}

void mainWindow::selectAllData()
{
	this->edt_output->selectAll();
}

#include "moc_mainwindow.cpp"

#endif // MAINWINDOW_H
