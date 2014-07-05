#include "mainwindow.h"

// TODO! Credit artua.com for the new app icon.

#include <QtGui>

int main(int argc, char *argv[])
{
	QApplication app(argc, argv);

	mainWindow wnd;
	wnd.show();

	return app.exec();

}
