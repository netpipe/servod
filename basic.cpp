#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <map>
#include <vector>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>

#define PORT 8080
#define BUFFER_SIZE 8192
#define WEBROOT "./www"  // Change to your document root

void send_response(int client_fd, const std::string& status, const std::string& content_type, const std::string& body) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    send(client_fd, oss.str().c_str(), oss.str().length(), 0);
}

std::string get_mime_type(const std::string& path) {
    if (path.ends_with(".html") || path.ends_with(".htm")) return "text/html";
    if (path.ends_with(".css")) return "text/css";
    if (path.ends_with(".js")) return "application/javascript";
    if (path.ends_with(".png")) return "image/png";
    if (path.ends_with(".jpg") || path.ends_with(".jpeg")) return "image/jpeg";
    if (path.ends_with(".gif")) return "image/gif";
    if (path.ends_with(".php")) return "text/html";
    return "text/plain";
}

void handle_php_cgi(int client_fd, const std::string& path, const std::string& query_string) {
    int cgi_output[2];
    pipe(cgi_output);
    pid_t pid = fork();

    if (pid == 0) {
        dup2(cgi_output[1], STDOUT_FILENO);
        close(cgi_output[0]);

        setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
        setenv("SCRIPT_FILENAME", path.c_str(), 1);
        setenv("QUERY_STRING", query_string.c_str(), 1);
        setenv("REQUEST_METHOD", "GET", 1);
        setenv("REDIRECT_STATUS", "200", 1);

        execlp("php-cgi", "php-cgi", NULL);
        perror("execlp");
        exit(1);
    } else {
        close(cgi_output[1]);
        waitpid(pid, NULL, 0);

        char buffer[BUFFER_SIZE];
        std::ostringstream oss;
        ssize_t bytes;
        while ((bytes = read(cgi_output[0], buffer, BUFFER_SIZE)) > 0) {
            oss.write(buffer, bytes);
        }
        close(cgi_output[0]);

        std::string output = oss.str();
        size_t header_end = output.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            output = output.substr(header_end + 4); // Strip CGI headers
        }

        send_response(client_fd, "200 OK", "text/html", output);
    }
}

void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE] = {0};
    recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
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
        send_response(client_fd, "404 Not Found", "text/plain", "404 Not Found");
        close(client_fd);
        return;
    }

    if (filepath.ends_with(".php")) {
        handle_php_cgi(client_fd, filepath, query_string);
    } else {
        std::ifstream file(filepath, std::ios::binary);
        std::ostringstream oss;
        oss << file.rdbuf();
        send_response(client_fd, "200 OK", get_mime_type(filepath), oss.str());
    }

    close(client_fd);
}

int main() {
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

    if (listen(server_fd, 10) == -1) {
        perror("listen");
        return 1;
    }

    std::cout << "Server started on port " << PORT << "\n";

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd == -1) continue;

        if (fork() == 0) {
            close(server_fd);
            handle_client(client_fd);
            exit(0);
        } else {
            close(client_fd);
        }
    }

    close(server_fd);
    return 0;
}
