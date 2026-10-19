// Qt 5.12+ Single-File HTTP/HTTPS Web Server with GUI
// Build with: qmake && make

#include <QApplication>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QWidget>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QSslCertificate>
#include <QSslKey>
#include <QProcess>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QMimeDatabase>
#include <QDateTime>
#include <QUrl>
#include <QDebug>

// Handles a single client connection (works for both HTTP and HTTPS)
class HttpConnection : public QObject {
    Q_OBJECT
public:
    explicit HttpConnection(QTcpSocket* socket, const QString& docRoot)
        : QObject(socket), socket(socket), docRoot(docRoot)
    {
        connect(socket, &QTcpSocket::readyRead, this, &HttpConnection::onReadyRead);
        connect(socket, &QTcpSocket::disconnected, this, &QObject::deleteLater);
    }

private:
    QTcpSocket* socket;
    QString docRoot;
    QByteArray buffer;

    QString method;
    QString path;
    QString query;
    QString host;
    QMap<QString, QString> headers;
    qint64 contentLength = 0;
    bool headersParsed = false;
    int headerEndPos = 0;

    void onReadyRead() {
        buffer.append(socket->readAll());

        if (!headersParsed) {
            headerEndPos = buffer.indexOf("\r\n\r\n");
            if (headerEndPos == -1) return; // Wait for full headers

            if (!parseHeaders()) {
                sendError(400, "Bad Request");
                return;
            }
            headersParsed = true;
        }

        if (headersParsed) {
            qint64 totalNeeded = headerEndPos + 4 + contentLength;
            if (buffer.size() < totalNeeded) return; // Wait for full body

            QByteArray body = buffer.mid(headerEndPos + 4, contentLength);
            buffer.clear(); // Free memory

            processRequest(body);
        }
    }

    bool parseHeaders() {
        QList<QByteArray> lines = buffer.left(headerEndPos).split('\n');
        if (lines.isEmpty()) return false;

        QList<QByteArray> requestLineParts = lines.first().split(' ');
        if (requestLineParts.size() < 2) return false;

        method = requestLineParts[0].toUpper();
        QString uri = requestLineParts[1];

        int qPos = uri.indexOf('?');
        if (qPos != -1) {
            path = QUrl::fromPercentEncoding(uri.left(qPos).toUtf8());
            query = uri.mid(qPos + 1);
        } else {
            path = QUrl::fromPercentEncoding(uri.toUtf8());
        }

        for (int i = 1; i < lines.size(); ++i) {
            QByteArray line = lines[i].trimmed();
            int colon = line.indexOf(':');
            if (colon > 0) {
                QString key = line.left(colon).trimmed().toLower();
                QString val = line.mid(colon + 1).trimmed();
                headers[key] = val;
                if (key == "host") host = val.split(':').first();
                if (key == "content-length") contentLength = val.toLongLong();
            }
        }

        if (host.isEmpty()) host = "localhost";
        return true;
    }

    void processRequest(const QByteArray& body) {
        // 1. Prevent Path Traversal (Security Fix)
        QStringList parts = path.split('/', QString::SkipEmptyParts);
        QStringList cleanParts;
        for (const QString& p : parts) {
            if (p == "..") {
                sendError(403, "Forbidden");
                return;
            }
            if (p != ".") cleanParts << p;
        }
        QString cleanPath = cleanParts.join('/');

        // 2. Virtual Host Support
        QString vHostDir = docRoot + "/" + host;
        if (!QDir(vHostDir).exists()) {
            vHostDir = docRoot; // Fallback to default root
        }

        QString filePath = vHostDir + "/" + cleanPath;

        // 3. Directory Index Handling
        if (QFileInfo(filePath).isDir()) {
            QString indexPath = filePath + "/index.php";
            if (QFileInfo(indexPath).exists()) {
                filePath = indexPath;
            } else {
                indexPath = filePath + "/index.html";
                if (QFileInfo(indexPath).exists()) {
                    filePath = indexPath;
                } else {
                    sendError(403, "Directory Listing Forbidden");
                    return;
                }
            }
        }

        QFileInfo fileInfo(filePath);
        if (!fileInfo.exists() || !fileInfo.absoluteFilePath().startsWith(QFileInfo(vHostDir).absoluteFilePath())) {
            sendError(404, "Not Found");
            return;
        }

        if (filePath.endsWith(".php", Qt::CaseInsensitive)) {
            runPhpCgi(fileInfo.absoluteFilePath(), body);
        } else {
            serveStaticFile(fileInfo.absoluteFilePath());
        }
    }

    void runPhpCgi(const QString& scriptPath, const QByteArray& body) {
        QProcess* php = new QProcess(this);

        // Set standard CGI environment variables so PHP works correctly
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();

        // ADD THIS LINE to bypass the force-cgi-redirect security check:
        env.insert("REDIRECT_STATUS", "200");

        env.insert("GATEWAY_INTERFACE", "CGI/1.1");
        env.insert("SERVER_SOFTWARE", "QtWebServer/1.0");
        env.insert("SERVER_PROTOCOL", "HTTP/1.1");
        env.insert("SERVER_NAME", host);
        env.insert("SERVER_PORT", QString::number(socket->localPort()));
        env.insert("REQUEST_METHOD", method);
        env.insert("REQUEST_URI", path + (query.isEmpty() ? "" : "?" + query));
        env.insert("SCRIPT_NAME", "/" + path.split('/').last());
        env.insert("SCRIPT_FILENAME", scriptPath);
        env.insert("DOCUMENT_ROOT", QFileInfo(scriptPath).absolutePath());
        env.insert("QUERY_STRING", query);
        env.insert("REMOTE_ADDR", socket->peerAddress().toString());

        if (!body.isEmpty()) {
            env.insert("CONTENT_LENGTH", QString::number(body.size()));
            if (headers.contains("content-type"))
                env.insert("CONTENT_TYPE", headers["content-type"]);
        }

        // Pass HTTP headers to PHP as HTTP_* variables
        for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
            if (it.key() != "content-type" && it.key() != "content-length") {
                env.insert("HTTP_" + it.key().toUpper().replace('-', '_'), it.value());
            }
        }

        php->setProcessEnvironment(env);

        // Asynchronous execution (Fixes GUI freezing)
        connect(php, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this, [this, php](int exitCode, QProcess::ExitStatus status) {
            QByteArray output = php->readAllStandardOutput();
            parseCgiOutput(output);
            php->deleteLater();
            socket->disconnectFromHost();
        });

        connect(php, &QProcess::errorOccurred, this, [this, php]() {
            sendError(500, "Failed to start PHP-CGI");
            php->deleteLater();
        });

        if (!body.isEmpty()) {
            php->start("php-cgi", QStringList() << scriptPath, QIODevice::ReadWrite);
            if (php->waitForStarted()) {
                php->write(body); // Send POST data to PHP
                php->closeWriteChannel();
            }
        } else {
            php->start("php-cgi", QStringList() << scriptPath, QIODevice::ReadOnly);
        }
    }

    void parseCgiOutput(const QByteArray& output) {
        int headerEnd = output.indexOf("\r\n\r\n");
        int sepLen = 4;
        if (headerEnd == -1) {
            headerEnd = output.indexOf("\n\n");
            sepLen = 2;
        }

        QByteArray headersPart;
        QByteArray bodyPart;
        if (headerEnd != -1) {
            headersPart = output.left(headerEnd);
            bodyPart = output.mid(headerEnd + sepLen);
        } else {
            bodyPart = output;
        }

        QList<QByteArray> lines = headersPart.split('\n');
        int statusCode = 200;
        QString statusText = "OK";
        QByteArray customHeaders;
        bool hasLocation = false;
        bool hasStatus = false;

        for (const QByteArray& line : lines) {
            QByteArray trimmed = line.trimmed();
            if (trimmed.isEmpty()) continue;

            // Handle NPH (Non-Parsed Headers) like "HTTP/1.1 200 OK"
            if (trimmed.startsWith("HTTP/")) {
                QList<QByteArray> parts = trimmed.split(' ');
                if (parts.size() >= 2) {
                    statusCode = parts[1].toInt();
                    if (parts.size() >= 3) statusText = parts.mid(2).join(' ');
                }
            }
            // Handle standard CGI "Status:" header
            else if (trimmed.toLower().startsWith("status:")) {
                hasStatus = true;
                QList<QByteArray> parts = trimmed.mid(7).trimmed().split(' ');
                if (!parts.isEmpty()) {
                    statusCode = parts[0].toInt();
                    if (parts.size() > 1) statusText = parts.mid(1).join(' ');
                }
            }
            // Track redirects
            else if (trimmed.toLower().startsWith("location:")) {
                hasLocation = true;
                customHeaders += trimmed + "\r\n";
            }
            else {
                customHeaders += trimmed + "\r\n";
            }
        }

        // If PHP sends a Location header without a status, assume 302 Redirect
        if (hasLocation && !hasStatus) statusCode = 302;

        QByteArray response = "HTTP/1.1 " + QByteArray::number(statusCode) + " " + statusText.toUtf8() + "\r\n";
        if (!customHeaders.isEmpty()) response += customHeaders;
        response += "Connection: close\r\n\r\n";
        response += bodyPart;

        socket->write(response);
        socket->flush();
    }

    void serveStaticFile(const QString& filePath) {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            sendError(500, "Internal Server Error");
            return;
        }

        // Fix: Use MIME database instead of hardcoding text/html
        QMimeDatabase mimeDb;
        QMimeType mime = mimeDb.mimeTypeForFile(filePath, QMimeDatabase::MatchExtension);
        QByteArray contentType = mime.isValid() ? mime.name().toUtf8() : "application/octet-stream";

        QByteArray response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: " + contentType + "\r\n";
        response += "Content-Length: " + QByteArray::number(file.size()) + "\r\n";
        response += "Connection: close\r\n\r\n";

        socket->write(response);
        socket->write(file.readAll());
        socket->flush();
        socket->disconnectFromHost();
    }

    void sendError(int code, const QString& text) {
        QByteArray body = QString("<html><body><h1>%1 %2</h1></body></html>")
                            .arg(code).arg(text).toUtf8();
        QByteArray response = "HTTP/1.1 " + QByteArray::number(code) + " " + text.toUtf8() + "\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
        response += "Connection: close\r\n\r\n";
        response += body;

        socket->write(response);
        socket->flush();
        socket->disconnectFromHost();
    }
};

class WebServer : public QObject {
    Q_OBJECT

public:
    WebServer(QObject *parent = nullptr) : QObject(parent) {
        httpServer = new QTcpServer(this);
        httpsServer = new QTcpServer(this);

        // Pre-load SSL configuration (Performance fix)
        QFile certFile(":/cert.pem");
        QFile keyFile(":/key.pem");
        if (certFile.open(QIODevice::ReadOnly) && keyFile.open(QIODevice::ReadOnly)) {
            sslConfig.setLocalCertificate(QSslCertificate(certFile.readAll(), QSsl::Pem));
            sslConfig.setPrivateKey(QSslKey(keyFile.readAll(), QSsl::Rsa, QSsl::Pem));
        }
    }

    void start(quint16 httpPort = 8080, quint16 httpsPort = 8443, const QString& docRoot = "www") {
        this->docRoot = docRoot;

        connect(httpServer, &QTcpServer::newConnection, this, &WebServer::handleHttpConnection);
        connect(httpsServer, &QTcpServer::newConnection, this, &WebServer::handleHttpsConnection);

        if (!httpServer->listen(QHostAddress::Any, httpPort))
            qWarning() << "Failed to start HTTP server on port" << httpPort;
        else
            qInfo() << "HTTP server running on port" << httpPort;

        if (!httpsServer->listen(QHostAddress::Any, httpsPort))
            qWarning() << "Failed to start HTTPS server on port" << httpsPort;
        else
            qInfo() << "HTTPS server running on port" << httpsPort;
    }

private slots:
    void handleHttpConnection() {
        QTcpSocket *socket = httpServer->nextPendingConnection();
        new HttpConnection(socket, docRoot);
    }

    void handleHttpsConnection() {
        QTcpSocket* tcpSocket = httpsServer->nextPendingConnection();
        QSslSocket* sslSocket = new QSslSocket(this);

        if (!sslSocket->setSocketDescriptor(tcpSocket->socketDescriptor())) {
            tcpSocket->deleteLater();
            sslSocket->deleteLater();
            return;
        }

        tcpSocket->setParent(nullptr);
        tcpSocket->deleteLater();

        sslSocket->setSslConfiguration(sslConfig);
        QObject::connect(sslSocket, SIGNAL(sslErrors(QList<QSslError>)),
                         sslSocket, SLOT(ignoreSslErrors()));
        // Hand off the encrypted socket to our generic connection handler
        connect(sslSocket, &QSslSocket::encrypted, this, [this, sslSocket]() {
            new HttpConnection(sslSocket, docRoot);
        });

        connect(sslSocket, &QSslSocket::disconnected, sslSocket, &QSslSocket::deleteLater);
        sslSocket->startServerEncryption();
    }

private:
    QTcpServer *httpServer;
    QTcpServer *httpsServer;
    QSslConfiguration sslConfig;
    QString docRoot;
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
    QObject::connect(startBtn, &QPushButton::clicked, [=] {
        server->start(8080, 8443, "www"); // Change "www" to your document root
        log->append("Server started on HTTP 8080 and HTTPS 8443");
    });

    window.show();
    return app.exec();
}

#include "main.moc"
