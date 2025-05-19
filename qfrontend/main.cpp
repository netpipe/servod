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

        layout->addWidget(portLabel);
        layout->addWidget(httpPort);
        layout->addWidget(httpsLabel);
        layout->addWidget(httpsPort);
        layout->addWidget(certLabel);
        layout->addWidget(certFile);
        layout->addWidget(keyLabel);
        layout->addWidget(keyFile);
        layout->addWidget(log);

        QTextEdit *logOutput = new QTextEdit;
        logOutput->setReadOnly(true);
        layout->addWidget(logOutput);

        serverProcess = new QProcess(this);
        logOutput->setReadOnly(true);

        QPushButton *startButton = new QPushButton("Start Webserver", this);
layout->addWidget(startButton);
        connect(startButton, &QPushButton::clicked, this, [=]() {
            if (serverProcess->state() == QProcess::NotRunning) {
                QString program = QApplication::applicationDirPath() +"/servod";  // adjust to full path if needed
                logOutput->append(program);
                QStringList args = {
                    "--http", httpPort->text(),
                    "--https", httpsPort->text(),
                    "--cert", certFile->text(),
                    "--key", keyFile->text()
                };

                serverProcess->start(program, args);
              //  QProcess::startDetached("./servod");
//serverProcess->startDetached(program);
              //  serverProcess->start(program);
                if (!serverProcess->waitForStarted(1000)) {
                    logOutput->append("❌ Failed to start servod.");
                    return;
                }

                logOutput->append("✅ servod started.");
            } else {
                logOutput->append("ℹ️ servod is already running.");
            }
        });

        connect(serverProcess, &QProcess::readyReadStandardOutput, this, [=]() {
            logOutput->append(QString::fromUtf8(serverProcess->readAllStandardOutput()));
        });

        connect(serverProcess, &QProcess::readyReadStandardError, this, [=]() {
            logOutput->append(QString::fromUtf8(serverProcess->readAllStandardError()));
        });

        connect(serverProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this, [=](int code, QProcess::ExitStatus status) {
            logOutput->append("❗️ servod exited with code: " + QString::number(code));
        });


    }

public slots:

private:
    QLineEdit *httpPort, *httpsPort, *certFile, *keyFile;
    QTextEdit* log;
    QProcess *serverProcess = nullptr;
    QTextEdit *logOutput = nullptr;
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
