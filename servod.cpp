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
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8443
#define BUFFER_SIZE 8192
#define WEBROOT "./www"
#define UPLOAD_DIR "./uploads"

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

void send_response(SSL* ssl, const std::string& status, const std::string& content_type, const std::string& body) {
    std::ostringstream oss;
    oss << "HTTP/1.0 " << status << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    SSL_write(ssl, oss.str().c_str(), oss.str().length());
}

void handle_php_cgi(SSL* ssl, const std::string& path, const std::string& query_string, const std::string& method, const std::string& post_data = "") {
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
        send_response(ssl, "200 OK", "text/html", out_str);
    }
}

std::string save_uploaded_file(const std::string& data, const std::string& boundary) {
    size_t start = data.find("\r\n\r\n");
    if (start == std::string::npos) return "";
    start += 4;
    size_t end = data.find(boundary, start);
    if (end == std::string::npos) return "";
    std::string content = data.substr(start, end - start);
    std::string filename = UPLOAD_DIR;
    filename += "/upload_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    std::ofstream out(filename, std::ios::binary);
    out.write(content.c_str(), content.size());
    out.close();
    return filename;
}

void handle_client(SSL* ssl) {
    char buffer[BUFFER_SIZE] = {0};
    int received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if (received <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
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

    std::string filepath = WEBROOT + url;
    if (filepath.back() == '/') filepath += "index.html";

    struct stat st;
    if (stat(filepath.c_str(), &st) == -1) {
        send_response(ssl, "404 Not Found", "text/plain", "404 Not Found");
        log("404 for " + filepath);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    std::string post_data;
    if (method == "POST") {
        std::string req(request);
        size_t cl_pos = req.find("Content-Length:");
        if (cl_pos != std::string::npos) {
            size_t len_start = req.find_first_of("0123456789", cl_pos);
            size_t len_end = req.find("\r\n", len_start);
            size_t content_length = std::stoul(req.substr(len_start, len_end - len_start));
            size_t body_pos = req.find("\r\n\r\n");
            if (body_pos != std::string::npos) {
                post_data = req.substr(body_pos + 4);
                while (post_data.length() < content_length) {
                    int more = SSL_read(ssl, buffer, BUFFER_SIZE);
                    if (more > 0) post_data.append(buffer, more);
                }
            }
        }
    }

    if (filepath.ends_with(".php")) {
        handle_php_cgi(ssl, filepath, query_string, method, post_data);
    } else if (url == "/upload" && method == "POST") {
        size_t bpos = request.find("boundary=");
        std::string boundary = (bpos != std::string::npos) ? "--" + request.substr(bpos + 9, request.find("\r\n", bpos) - bpos - 9) : "";
        std::string filename = save_uploaded_file(post_data, boundary);
        send_response(ssl, "200 OK", "text/plain", "File uploaded: " + filename);
    } else {
        std::ifstream file(filepath, std::ios::binary);
        std::ostringstream oss;
        oss << file.rdbuf();
        send_response(ssl, "200 OK", get_mime_type(filepath), oss.str());
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main() {
    mkdir(UPLOAD_DIR, 0755);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(server_fd, (sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 16);

    log("HTTPS Server started on port " + std::to_string(PORT));

    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (sockaddr*)&client_addr, &client_len);
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            SSL_free(ssl);
            continue;
        }
        std::thread([ssl]() {
            handle_client(ssl);
        }).detach();
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
