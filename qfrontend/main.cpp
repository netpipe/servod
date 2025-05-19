// full_gui_server.cpp
#include <QApplication>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>
#include <QLineEdit>
#include <QTextEdit>
#include <QThread>
#include <QLabel>
#include <QTcpSocket>
#include <QProcess>
#include <QFile>
#include <QMap>
#include <QDebug>

// Simplified config struct
struct ServerConfig {
    int httpPort = 8080;
    int httpsPort = 8443;
    QString certFile;
    QString keyFile;
    bool useHttps = true;
    QMap<QString, QString> virtualHosts;  // hostname -> docroot
};

class ServerWindow : public QWidget {
    Q_OBJECT
public:
    ServerWindow() {
        auto* layout = new QVBoxLayout(this);
        auto* portLabel = new QLabel("HTTP Port:");
        auto* httpsLabel = new QLabel("HTTPS Port:");
        auto* certLabel = new QLabel("Certificate:");
        auto* keyLabel = new QLabel("Key:");

        httpPort = new QLineEdit("8080");
        httpsPort = new QLineEdit("8443");
        certFile = new QLineEdit("cert.pem");
        keyFile = new QLineEdit("key.pem");

        log = new QTextEdit();
        log->setReadOnly(true);

        auto* startBtn = new QPushButton("Start Server");
        layout->addWidget(portLabel);
        layout->addWidget(httpPort);
        layout->addWidget(httpsLabel);
        layout->addWidget(httpsPort);
        layout->addWidget(certLabel);
        layout->addWidget(certFile);
        layout->addWidget(keyLabel);
        layout->addWidget(keyFile);
        layout->addWidget(startBtn);
        layout->addWidget(log);

        connect(startBtn, &QPushButton::clicked, this, &ServerWindow::startServer);
    }

public slots:
    void startServer() {
        ServerConfig cfg;
        cfg.httpPort = httpPort->text().toInt();
        cfg.httpsPort = httpsPort->text().toInt();
        cfg.certFile = certFile->text();
        cfg.keyFile = keyFile->text();

        cfg.virtualHosts.insert("localhost", "www");

        //server = new WebServer(cfg, this);
        //connect(server, &QThread::finished, this, [this]() {
        //    log->append("Server stopped.");
       // });

        log->append("Starting server...");
        //server->start();
    }

private:
    QLineEdit *httpPort, *httpsPort, *certFile, *keyFile;
    QTextEdit* log;
    //WebServer* server = nullptr;
};

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    ServerWindow window;
    window.setWindowTitle("Secure Qt Web Server");
    window.resize(400, 400);
    window.show();
    return app.exec();
}

#include "main.moc"
