// Single-file HTTP + HTTPS Web Server with PHP/CGI and SQLite support
// Compile with: g++ -std=c++17 -O2 -o webserver webserver.cpp -lssl -lcrypto

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <cstring>
#include <unordered_map>

#define HTTP_PORT 8080
#define HTTPS_PORT 8443
#define BUFFER_SIZE 8192

const std::string www_root = "www";

std::unordered_map<std::string, std::string> mime_types = {
    {".html", "text/html"},
    {".htm", "text/html"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".svg", "image/svg+xml"},
    {".txt", "text/plain"},
    {".pdf", "application/pdf"},
};

std::string get_mime_type(const std::string& path) {
    size_t dot = path.find_last_of('.');
    if (dot != std::string::npos) {
        std::string ext = path.substr(dot);
        if (mime_types.count(ext)) return mime_types[ext];
    }
    return "application/octet-stream";
}

int create_listening_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    bind(sock, (sockaddr*)&addr, sizeof(addr));
    listen(sock, SOMAXCONN);
    return sock;
}

bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

void send_response(int client, const std::string& status, const std::string& content_type, const std::string& body) {
    std::ostringstream response;
    response << "HTTP/1.1 " << status << "\r\n";
    response << "Content-Type: " << content_type << "\r\n";
    response << "Content-Length: " << body.size() << "\r\n\r\n";
    response << body;
    send(client, response.str().c_str(), response.str().size(), 0);
}

void run_php_script(int client, const std::string& script_path, const std::string& method, const std::string& content_type, int content_length, const std::string& post_data) {
    int pipe_in[2], pipe_out[2];
    pipe(pipe_in);
    pipe(pipe_out);

    pid_t pid = fork();
    if (pid == 0) {
        dup2(pipe_in[0], 0);
        dup2(pipe_out[1], 1);
        close(pipe_in[1]);
        close(pipe_out[0]);
        setenv("SCRIPT_FILENAME", script_path.c_str(), 1);
        setenv("REQUEST_METHOD", method.c_str(), 1);
        setenv("CONTENT_TYPE", content_type.c_str(), 1);
        setenv("CONTENT_LENGTH", std::to_string(content_length).c_str(), 1);
        execlp("php-cgi", "php-cgi", nullptr);
        exit(1);
    } else {
        close(pipe_in[0]);
        close(pipe_out[1]);

        if (!post_data.empty()) write(pipe_in[1], post_data.c_str(), post_data.size());
        close(pipe_in[1]);

        char buffer[BUFFER_SIZE];
        ssize_t bytes;
        std::ostringstream raw_output;
        while ((bytes = read(pipe_out[0], buffer, BUFFER_SIZE)) > 0) {
            raw_output.write(buffer, bytes);
        }
        close(pipe_out[0]);

        std::string full_output = raw_output.str();
        size_t header_end = full_output.find("\r\n\r\n");
        if (header_end == std::string::npos)
            header_end = full_output.find("\n\n");

        std::string body;
        if (header_end != std::string::npos) {
            body = full_output.substr(header_end + ((full_output[header_end] == '\r') ? 4 : 2));
        } else {
            body = full_output;
        }

        send_response(client, "200 OK", "text/html", body);
        waitpid(pid, nullptr, 0);
    }
}

void handle_request(int client, SSL* ssl = nullptr) {
    char buffer[BUFFER_SIZE];
    int bytes = ssl ? SSL_read(ssl, buffer, BUFFER_SIZE) : recv(client, buffer, BUFFER_SIZE, 0);
    if (bytes <= 0) {
        if (ssl) SSL_free(ssl);
        close(client);
        return;
    }

    std::string raw_request(buffer, bytes);
    std::istringstream request(raw_request);
    std::string method, path, version;
    request >> method >> path >> version;

    std::string content_type, post_data;
    int content_length = 0;
    std::string line;
    while (std::getline(request, line) && line != "\r") {
        if (line.find("Content-Type:") != std::string::npos)
            content_type = line.substr(line.find(":") + 2);
        else if (line.find("Content-Length:") != std::string::npos)
            content_length = std::stoi(line.substr(line.find(":") + 2));
    }

    if (method == "POST" && content_length > 0) {
        post_data = raw_request.substr(raw_request.find("\r\n\r\n") + 4);
        while ((int)post_data.size() < content_length) {
            char tmp[BUFFER_SIZE];
            int more = ssl ? SSL_read(ssl, tmp, BUFFER_SIZE) : recv(client, tmp, BUFFER_SIZE, 0);
            if (more <= 0) break;
            post_data.append(tmp, more);
        }
    }

    if (path == "/") path = "/index.php";
    std::string full_path = www_root + path;

    struct stat st;
    if (stat(full_path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        if (full_path.back() != '/') full_path += '/';
        std::vector<std::string> index_files = {"index.php", "index.html"};
        for (const auto& idx : index_files) {
            std::string try_path = full_path + idx;
            if (stat(try_path.c_str(), &st) == 0) {
                full_path = try_path;
                break;
            }
        }
    }

    if (stat(full_path.c_str(), &st) == 0) {
        if (ends_with(full_path, ".php")) {
            run_php_script(client, full_path, method, content_type, content_length, post_data);
        } else {
            std::ifstream file(full_path, std::ios::binary);
            std::ostringstream ss;
            ss << file.rdbuf();
            send_response(client, "200 OK", get_mime_type(full_path), ss.str());
        }
    } else {
        send_response(client, "404 Not Found", "text/plain", "File not found");
    }

    if (ssl) SSL_shutdown(ssl), SSL_free(ssl);
    close(client);
}

int main() {
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);

    int http_sock = create_listening_socket(HTTP_PORT);
    int https_sock = create_listening_socket(HTTPS_PORT);

    fd_set readfds;
    int maxfd = std::max(http_sock, https_sock) + 1;

    std::cout << "HTTP on port " << HTTP_PORT << ", HTTPS on port " << HTTPS_PORT << std::endl;

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(http_sock, &readfds);
        FD_SET(https_sock, &readfds);

        if (select(maxfd, &readfds, nullptr, nullptr, nullptr) < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(http_sock, &readfds)) {
            int client = accept(http_sock, nullptr, nullptr);
            std::thread(handle_request, client, nullptr).detach();
        }

        if (FD_ISSET(https_sock, &readfds)) {
            int client = accept(https_sock, nullptr, nullptr);
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client);
            if (SSL_accept(ssl) <= 0) {
                SSL_free(ssl);
                close(client);
            } else {
                std::thread(handle_request, client, ssl).detach();
            }
        }
    }

    close(http_sock);
    close(https_sock);
    SSL_CTX_free(ctx);
    return 0;
}
