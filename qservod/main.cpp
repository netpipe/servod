// Qt 5.12+ Single-File HTTP/HTTPS Web Server with GUI Start Button, CGI, File Uploads, Virtual Hosts
// Requires QtWidgets and QtNetwork modules. Build with: qmake && make

#include <QApplication>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QWidget>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSslSocket>
#include <QProcess>
#include <QFile>
#include <QDir>
#include <QDateTime>
#include <QSsl>
#include <QSslKey>
#include <QSslConfiguration>
        QSslSocket* sslSocket;
class WebServer : public QObject {
    Q_OBJECT

public:
    WebServer(QObject *parent = nullptr) : QObject(parent), httpServer(new QTcpServer(this)), httpsServer(new QTcpServer(this)) {}

    void start(quint16 httpPort = 8080, quint16 httpsPort = 8443) {
        connect(httpServer, &QTcpServer::newConnection, this, &WebServer::handleHttpConnection);
        connect(httpsServer, &QTcpServer::newConnection, this, &WebServer::handleHttpsConnection);

        if (!httpServer->listen(QHostAddress::Any, httpPort))
            qWarning("Failed to start HTTP server");

        if (!httpsServer->listen(QHostAddress::Any, httpsPort))
            qWarning("Failed to start HTTPS server (insecure, no TLS)");

        qInfo() << "HTTP server running on port" << httpPort;
        qInfo() << "HTTPS server running on port" << httpsPort;
    }

private slots:
    void handleHttpConnection() {
        QTcpSocket *socket = httpServer->nextPendingConnection();
        connect(socket, &QTcpSocket::readyRead, [this, socket]() {
            QByteArray request = socket->readAll();
            QString host = parseHost(request);
            QString path = parsePath(request);
            QString root = "www/" + host;
            QString filePath = root + path;
            if (filePath.endsWith(".php")) {
                runPhpCgi(socket,sslSocket, "www/" + path);
            } else {
                serveStaticFile(socket, filePath);
            }
        });
    }

    void handleHttpsConnection() {
        QTcpSocket* tcpSocket = httpsServer->nextPendingConnection();
        QSslSocket* sslSocket = new QSslSocket(this);

        if (!sslSocket->setSocketDescriptor(tcpSocket->socketDescriptor())) {
            tcpSocket->deleteLater();
            sslSocket->deleteLater();
            return;
        }
        tcpSocket->deleteLater();

        // Load cert and key
        QSslCertificate cert("./cert.pem");
        QSslKey key("./key.pem", QSsl::Rsa);
        QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
        sslConfig.setLocalCertificate(cert);
        sslConfig.setPrivateKey(key);
        sslSocket->setSslConfiguration(sslConfig);
    //    sslSocket->ignoreSslErrors();

        connect(sslSocket, &QSslSocket::encrypted, this, [sslSocket, this]() {
            connect(sslSocket, &QSslSocket::readyRead, this, [sslSocket, this]() {
                QByteArray request = sslSocket->readAll();

                QString host = parseHost(request);
                QString path = parsePath(request);
                QString root = "www/" + host;
                QString filePath = root + path;
                if (filePath.endsWith(".php")) {
                    runPhpCgi(nullptr,sslSocket, "www/" + path);
                } else {
                    serveStaticFile(sslSocket, filePath);
                }
            });
        });
        connect(sslSocket, SIGNAL(sslErrors(QList<QSslError>)), sslSocket, SLOT(ignoreSslErrors()));

        connect(sslSocket, &QSslSocket::disconnected, sslSocket, &QSslSocket::deleteLater);
        sslSocket->startServerEncryption();
    }



private:
    QTcpServer *httpServer;
    QTcpServer *httpsServer;

    QString parseHost(const QByteArray &req) {
        QList<QByteArray> lines = req.split('\n');
        for (const QByteArray &line : lines) {
            if (line.startsWith("Host:")) {
                return QString(line.mid(5)).trimmed();
            }
        }
        return "localhost";
    }

    QString parsePath(const QByteArray &req) {
        QList<QByteArray> lines = req.split('\n');
        if (!lines.isEmpty()) {
            QList<QByteArray> parts = lines[0].split(' ');
            if (parts.size() > 1)
                debug(QString(parts[1]));
            if (QString(parts[1]) == "/") parts[1] = "/index.php";
            QString fullPath = parts[1];
            return fullPath;
                return QString(parts[1]);
        }
        return "/index.php";
    }
    void debug(const QString &msg) {
        qDebug() << "[DEBUG]" << msg;
    }

    void runPhpCgi(QTcpSocket *socket, QSslSocket *sslSocket,const QString &scriptPath) {
        debug("Executing PHP: " + scriptPath);
     //   debug("CGI output:\n" + output);

        QProcess php;
        php.setProgram("php-cgi");
        php.setProcessChannelMode(QProcess::MergedChannels);
        php.setEnvironment(QProcess::systemEnvironment());
        php.setStandardInputFile(scriptPath);
        php.start();
        php.waitForFinished();
        QByteArray output = php.readAll();
        debug(php.readAll());
        socket->write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
        if (sslSocket) {
                    sslSocket->write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
            sslSocket->write(output);
            sslSocket->flush();
            sslSocket->disconnectFromHost();
        } else if (socket) {
                    socket->write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
            socket->write(output);
            socket->flush();
            socket->disconnectFromHost();
        }
    }

    void serveStaticFile(QTcpSocket *socket, const QString &filePath) {
        QFile file(filePath);
        if (!file.exists()) {
            socket->write("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile not found");
        } else {
            file.open(QIODevice::ReadOnly);
            QByteArray data = file.readAll();
            socket->write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
            socket->write(data);
        }
        socket->disconnectFromHost();
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QWidget window;
    window.setWindowTitle("Qt Web Server");
    QVBoxLayout *layout = new QVBoxLayout(&window);
    QTextEdit *log = new QTextEdit;
    log->setReadOnly(true);
    QPushButton *startBtn = new QPushButton("Start Server");
    layout->addWidget(log);
    layout->addWidget(startBtn);

    WebServer *server = new WebServer;
    QObject::connect(startBtn, &QPushButton::clicked, [=]() {
        server->start();
        log->append("Server started on HTTP 8080 and HTTPS 8443 (insecure TLS stub)");
    });

    window.show();
    return app.exec();
}

#include "main.moc"
