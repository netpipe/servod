// full_gui_server.cpp
#include <QApplication>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>
#include <QLineEdit>
#include <QTextEdit>
#include <QThread>
#include <QLabel>
#include <QProcess>
#include <QFile>
#include <QMap>
#include <QDebug>
#include <QProcess>

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

        QTextEdit *logOutput = new QTextEdit;
        logOutput->setReadOnly(true);
        layout->addWidget(logOutput);

        QProcess *serverProcess = new QProcess();

        QObject::connect(startBtn, &QPushButton::clicked, [&]() {
            if (serverProcess->state() == QProcess::NotRunning) {
                // Replace with your actual binary path and args
                QString program = "servod";
                QStringList args = {
                    "--http-port", httpPort->text(),
                    "--https-port", httpsPort->text(),
                    "--cert", certFile->text(),
                    "--key", keyFile->text()
                };

                serverProcess->start(program, args);
                logOutput->append("Starting server...");
            } else {
                logOutput->append("Server already running.");
            }
        });

        QObject::connect(serverProcess, &QProcess::readyReadStandardOutput, [&]() {
            logOutput->append(QString::fromUtf8(serverProcess->readAllStandardOutput()));
        });

        QObject::connect(serverProcess, &QProcess::readyReadStandardError, [&]() {
            logOutput->append(QString::fromUtf8(serverProcess->readAllStandardError()));
        });

        QObject::connect(serverProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                         [&](int exitCode, QProcess::ExitStatus) {
            logOutput->append("Server exited with code: " + QString::number(exitCode));
        });



    }

public slots:

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
