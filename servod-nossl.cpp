#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <filesystem>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sqlite3.h>

#define PORT 8080
#define BUFFER_SIZE 8192
#define WEBROOT "./www"

std::mutex log_mutex;

void log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::cerr << "[" << std::put_time(std::localtime(&now), "%F %T") << "] " << msg << "\n";
}

std::string get_mime_type(const std::string& path) {
    if (path.ends_with(".html")) return "text/html";
    if (path.ends_with(".css")) return "text/css";
    if (path.ends_with(".js")) return "application/javascript";
    if (path.ends_with(".png")) return "image/png";
    if (path.ends_with(".jpg") || path.ends_with(".jpeg")) return "image/jpeg";
    if (path.ends_with(".gif")) return "image/gif";
    if (path.ends_with(".php")) return "text/html";
    return "application/octet-stream";
}

void handle_sql_query(SSL* ssl, const std::string& query) {
    sqlite3* db;
    sqlite3_stmt* stmt;

    if (sqlite3_open("webdata.db", &db) != SQLITE_OK) {
        send_response(ssl, "500 Internal Server Error", "text/plain", "Database error");
        return;
    }

    std::ostringstream result;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        int cols = sqlite3_column_count(stmt);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            for (int i = 0; i < cols; ++i) {
                result << sqlite3_column_name(stmt, i) << "="
                       << (const char*)sqlite3_column_text(stmt, i) << "; ";
            }
            result << "\\n";
        }
    } else {
        result << "SQL error: " << sqlite3_errmsg(db);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    send_response(ssl, "200 OK", "text/plain", result.str());
}

void send_response(int client_fd, const std::string& status, const std::string& content_type, const std::string& body) {
    std::ostringstream oss;
    oss << "HTTP/1.0 " << status << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    send(client_fd, oss.str().c_str(), oss.str().length(), 0);
}

void handle_php_cgi(int client_fd, const std::string& path, const std::string& query_string, const std::string& method, const std::string& post_data = "") {
    int cgi_output[2], cgi_input[2];
    pipe(cgi_output);
    pipe(cgi_input);
    pid_t pid = fork();

    if (pid == 0) {
        dup2(cgi_output[1], STDOUT_FILENO);
        dup2(cgi_input[0], STDIN_FILENO);
        close(cgi_output[0]);
        close(cgi_input[1]);

        setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
        setenv("SCRIPT_FILENAME", path.c_str(), 1);
        setenv("QUERY_STRING", query_string.c_str(), 1);
        setenv("REQUEST_METHOD", method.c_str(), 1);
        setenv("REDIRECT_STATUS", "200", 1);
        if (method == "POST") {
            setenv("CONTENT_LENGTH", std::to_string(post_data.size()).c_str(), 1);
        }

        execlp("php-cgi", "php-cgi", NULL);
        perror("execlp");
        exit(1);
    } else {
        close(cgi_output[1]);
        close(cgi_input[0]);
        if (method == "POST") {
            write(cgi_input[1], post_data.c_str(), post_data.size());
        }
        close(cgi_input[1]);

        std::ostringstream output;
        char buffer[BUFFER_SIZE];
        ssize_t bytes;
        while ((bytes = read(cgi_output[0], buffer, BUFFER_SIZE)) > 0) {
            output.write(buffer, bytes);
        }
        close(cgi_output[0]);
        waitpid(pid, NULL, 0);

        std::string out_str = output.str();
        size_t header_end = out_str.find("\r\n\r\n");
        std::string body = (header_end != std::string::npos) ? out_str.substr(header_end + 4) : out_str;

        send_response(client_fd, "200 OK", "text/html", body);
    }
}

void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE] = {0};
    ssize_t received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    if (received <= 0) {
        close(client_fd);
        return;
    }

    std::string request(buffer);
    std::istringstream iss(request);
    std::string method, url, version;
    iss >> method >> url >> version;

    std::string query_string;
    size_t qs_pos = url.find('?');
    if (qs_pos != std::string::npos) {
        query_string = url.substr(qs_pos + 1);
        url = url.substr(0, qs_pos);
    }

if (url.starts_with("/query") && method == "GET") {
    std::string sql = query_string.substr(query_string.find("sql=") + 4);
    sql = url_decode(sql);  // You'll need a helper to decode %20 etc.
    handle_sql_query(ssl, sql);
}

    std::string filepath = WEBROOT + url;
    if (filepath.back() == '/') filepath += "index.html";

    struct stat st;
    if (stat(filepath.c_str(), &st) == -1) {
        send_response(client_fd, "404 Not Found", "text/plain", "404 Not Found");
        log("404 for " + filepath);
        close(client_fd);
        return;
    }

    if (filepath.ends_with(".php")) {
        std::string post_data;
        if (method == "POST") {
            std::string line;
            while (std::getline(iss, line) && line != "\r") {}
            size_t content_length = 0;
            size_t pos = request.find("Content-Length:");
            if (pos != std::string::npos) {
                content_length = std::stoi(request.substr(pos + 15));
            }
            post_data = request.substr(request.size() - content_length);
        }
        handle_php_cgi(client_fd, filepath, query_string, method, post_data);
    } else {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            send_response(client_fd, "500 Internal Server Error", "text/plain", "File open error");
            close(client_fd);
            return;
        }
        std::ostringstream oss;
        oss << file.rdbuf();
        send_response(client_fd, "200 OK", get_mime_type(filepath), oss.str());
    }

    close(client_fd);
}

void server_loop(int server_fd) {
    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd == -1) continue;

        std::thread([client_fd]() {
            handle_client(client_fd);
        }).detach();
    }
}

int main() {
    signal(SIGCHLD, SIG_IGN); // Prevent zombie processes

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 16) == -1) {
        perror("listen");
        return 1;
    }

    log("Server started on port " + std::to_string(PORT));
    server_loop(server_fd);

    close(server_fd);
    return 0;
}
