#ifndef WHOIS_INFO_H
#define WHOIS_INFO_H

#include <algorithm>

#include <QtGlobal>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QStatusBar>
#include <QRegExp>
#include <QFile>
#include <QTcpSocket>
#include <QHostAddress>

class WhoisInfo : public QObject
{
	Q_OBJECT

private:
	QStatusBar *status;

	QString addr;
	QString data;
	QString getField(QString, QString*);
	QString searchFields(QString, QString*);

	void parseData();

public:
	WhoisInfo(QStatusBar*);

	void query(QString, QString);
	void showStatus(QString);
	QString outputPlainText();
	QString getCIDR(QString);

	QString LastQuery;

	QString IP;
	QString IPRange;
	QString CIDR;
	QString Address;
	QString Country;
	QString Description;

};

WhoisInfo::WhoisInfo(QStatusBar *statusbar)
{
	this->status = statusbar;
}

void WhoisInfo::query(QString query_string, QString server="")
{
	QTcpSocket sock;
	QString cmd;

	data = "";

	if(!query_string.isEmpty())
	{
		query_string = query_string.toLower();
		if(server.isEmpty())
		{
			// This is a brand new query so reset all public properties of class.
			this->IP = "";
			this->IPRange = "";
			this->Address = "";
			this->CIDR = "";
			this->Country = "";
			this->Description = "";

			this->LastQuery = query_string;

			//Are we looking at an IP address or domain?
			int count = query_string.count(".", Qt::CaseInsensitive);
			if(count == 3)//IP address.
			{
				server = "whois.arin.net";
				IP = query_string;
				query_string = "n "+query_string+"\n";
			}
			else//Probably a domain name.
			{
				QStringList split = query_string.split(".");
				QString tld = split.at(split.count()-1);
				server = tld+".whois-servers.net";
				query_string = "domain "+query_string+"\n";
			}
		}
		else
		{
			query_string = query_string+"\n";
		}

		this->showStatus("Connecting to "+server);

		sock.connectToHost(server, 43);

		if(!sock.waitForConnected(5000))
		{
			this->showStatus("Connection timed out");
			return;
		}
		else
		{
			this->showStatus("Sending query: "+query_string);
			sock.write(query_string.toLatin1());
		}

		while(sock.bytesAvailable() < (int)sizeof(quint16))
		{
			if(sock.waitForReadyRead(2000))
			{
				data += sock.readAll();
			}
			else
			{
				// Is there any more info on this address?
				if(data.indexOf("rwhois") < 0)//We'll get to Remote Whois later.
				{
					QString ref_server = this->searchFields("ReferralServer|Whois Server", &data);

					if(!ref_server.isEmpty())
					{
						this->showStatus("Found referral server: "+ref_server);

						ref_server = ref_server.remove("whois://");
						ref_server = ref_server.remove(":43");

						this->showStatus("Querying again: "+query_string+" on "+ref_server);

						query_string.remove("domain ", Qt::CaseInsensitive);
						query_string.remove("n ", Qt::CaseInsensitive);
						query_string.remove("\n", Qt::CaseInsensitive);
						query(query_string.trimmed(), ref_server);

					}
					else
					{
						parseData();
						this->showStatus("");
					}
				}

				return;
			}
		}
	}
}

void WhoisInfo::showStatus(QString msg)
{
	qDebug() << msg;
	if(status){ this->status->showMessage(msg); }
}

void WhoisInfo::parseData()
{
	int x;
	QStringList chunks;
	QString chunk;
	QStringList lines;
	QString line;
	QStringList pair;

	// APNIC	220.181.7.82
	// RIPE		93.36.206.8
	// LACNIC	148.233.159.58

	this->data.remove("\r", Qt::CaseInsensitive); // LANIC uses \r\n

	// Data from foreign countries is delivered within a context
	// ie. descr, address, person, etc could be for anything.. So
	// we have to cut the data into smaller chunks before eating it.
	chunks = data.split("\n\n", QString::SkipEmptyParts, Qt::CaseInsensitive);

	if(chunks.count() > 0)
	{
		// Roll through all the chunks until we're full.
		for(x=0; x<chunks.count(); x++)
		{
			chunk = chunks.at(x);

			// Nibble at the various parts we're after. (IP, description, etc).
			if(this->IPRange.isEmpty())
			{
				this->IPRange = getField("inetnum|NetRange", &chunk);
				this->CIDR = this->getCIDR(this->IPRange);
			}

			if(this->Description.isEmpty())
			{
				this->Description = getField("descr|OrgName|owner|responsible", &chunk);
			}

			if(this->Country.isEmpty())
			{
				this->Country = getField("country", &chunk);

				QFile file(":resources/text/countries.txt");
				if(file.open(QIODevice::ReadOnly))
				{
					while(!file.atEnd())
					{
						if(file.isOpen())
						{
							line = file.readLine(255);
							if(!line.isEmpty())
							{
								pair = line.split(",", QString::SkipEmptyParts, Qt::CaseInsensitive);
								if(pair.count() > 1)
								{
									if(pair.at(0) == this->Country)
									{
										this->Country = pair.at(1);
										file.close();
									}
								}
							}
						}
					}
				}
			}

			if(this->Address.isEmpty())
			{
				this->Address = getField("address|City|StateProv|PostalCode", &chunk);
			}
		}
	}

	if(data.indexOf("CIDR") <0)
	{
		if(!this->IPRange.isEmpty() && !this->CIDR.isEmpty())
		{
			data.replace(this->IPRange, this->IPRange+"\nCIDR:"+this->CIDR);
		}
	}
}

QString WhoisInfo::getField(QString field, QString *chunk)
{
	int pos = 0;
	int offset = 0;
	QString txt = "";
	QRegExp r;

	r.setPattern("(?:"+field+"):([^\\n]*)");
	r.setCaseSensitivity(Qt::CaseInsensitive);

	while(pos >= 0)
	{
		pos = r.indexIn(*chunk, offset);
		if(r.captureCount() > 0)
		{
			txt += r.cap(1).trimmed() + "\n";
			offset = pos + r.cap(1).length();
		}
	}

	return txt.trimmed();
}

QString WhoisInfo::searchFields(QString field, QString *text)
{
	QRegExp r;
	QString result;

	r.setPattern("(?:"+field+"):([^\\n]*)");
	r.setCaseSensitivity(Qt::CaseInsensitive);
	r.indexIn(*text);
	if(r.captureCount() > 0)
	{
		result = r.cap(1).trimmed();
	}
	return result;
}

QString WhoisInfo::outputPlainText()
{
	QString plain;
	QString line;
	QStringList half;

	// Let's do some cleanup..
	QStringList lines = data.split("\n");
	for(int x=0; x< lines.count(); x++)
	{
		// Qt Creator auto-complete fails when lines.at(x).SomeMethod
		// So we go long-hand.
		line = lines.at(x);
		if(line.left(1) != "#" && line.left(1) != "%")
		{
			if(line.indexOf(":") >= 0)
			{
				half = line.split(":");
				if(half.count() == 2)
				{
					line = half.at(0).trimmed() + ":\t" + half.at(1).trimmed();
				}
			}
		}
		plain += line + "\n";
	}

	return plain;
}

QString WhoisInfo::getCIDR(QString range)
{
	QString out;
	QStringList pair;

	pair = range.split("-", QString::SkipEmptyParts);
	if(pair.count() == 2)
	{
		QString block;
		QHostAddress addr1(pair.at(0));
		QHostAddress addr2(pair.at(1));

		qint32 a1;
		qint32 a2;
		qint32 diff;

		a1 = addr1.toIPv4Address();
		a2 = addr2.toIPv4Address();
		diff = std::max(a1, a2) - std::min(a1, a2);

		qDebug() << "Diff: "+QString::number(diff);

		switch(diff)
		{

		case 31:
			block = "/27";
			break;
		case 63:
			block = "/26";
			break;
		case 127:
			block = "/25";
			break;
		case 255:
			block = "/24";
			break;
		case 511:
			block = "/23";
			break;
		case 1023:
			block = "/22";
			break;
		case 2047:
			block = "/21";
			break;
		case 4095:
			block = "/20";
			break;
		case 8191:
			block = "/19";
			break;
		case 16383:
			block = "/18";
			break;
		case 32767:
			block = "/17";
			break;
		case 65535:
			block = "/16";
			break;
		case 131071:
			block = "/15";
			break;
		case 262143:
			block = "/14";
			break;
		case 524287:
			block = "/13";
			break;

		case 1048575:
			block = "/12";
			break;
		case 2097151:
			block = "/11";
			break;
		case 4194303:
			block = "/10";
			break;
		case 8388607:
			block = "/9";
			break;
		case 16777215:
			block = "/8";
			break;
		}

		if(!block.isEmpty())
		{
			qDebug() << "Calculated CIDR: " + addr1.toString() + block;
			out = addr1.toString()+block;
		}
		else
		{
			qDebug() << "Couldn't calculate CIDR";
			// Maybe someone could help with this?
			out = "Unknown";
		}

	}
	else
	{
		out = "Unknown";
	}

	return out;
}

#include "moc_whoisinfo.cpp"

#endif // WHOIS_INFO_H
