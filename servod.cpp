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
#include <sstream>
#include <fstream>
#include <iostream>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <string>
#include <cassert>
#include <string_view>

int HTTP_PORT = 8080;
int HTTPS_PORT = 8443;
bool https_enabled = true;
#define BUFFER_SIZE 8192
#define WEBROOT "./www"
#define UPLOAD_DIR "./uploads"

bool ends_with(const std::string& suffix, const std::string& str) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::unordered_map<std::string, std::string> vhosts = {
    {"localhost", "www"},
    {"example.com", "www/example"},
    {"test.local",  "www/testsite"},
};

std::mutex log_mutex;

void log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::cerr << "[" << std::put_time(std::localtime(&now), "%F %T") << "] " << msg << "\n";
}

std::string get_mime_type(const std::string& path) {
    if (ends_with(".html",path)) return "text/html";
    if (ends_with(".css",path)) return "text/css";
    if (ends_with(".js",path)) return "application/javascript";
    if (ends_with(".png",path)) return "image/png";
    if (ends_with(".jpg",path) || ends_with(".jpeg",path)) return "image/jpeg";
    if (ends_with(".gif",path)) return "image/gif";
    if (ends_with(".php",path)) return "text/html";
    return "application/octet-stream";
}

void send_response(int client, SSL* ssl, const std::string& status, const std::string& content_type, const std::string& body) {
    std::ostringstream oss;
    oss << "HTTP/1.0 " << status << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;

    const std::string response = oss.str();
    if (ssl) {
        SSL_write(ssl, response.c_str(), response.length());
    } else {
        send(client, response.c_str(), response.length(), 0);
    }
}

void handle_php_cgi(int client,SSL* ssl, const std::string& path, const std::string& query_string, const std::string& method, const std::string& post_data = "") {
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
std::ostringstream raw_output;
while ((bytes = read(cgi_output[0], buffer, BUFFER_SIZE)) > 0) {
    raw_output.write(buffer, bytes);
}

std::string full_output = raw_output.str();

// Find header/body split — marked by double CRLF
size_t header_end = full_output.find("\r\n\r\n");
if (header_end == std::string::npos) {
    // fallback if LF only
    header_end = full_output.find("\n\n");
}

std::string headers, body;
if (header_end != std::string::npos) {
    headers = full_output.substr(0, header_end);
    body = full_output.substr(header_end + ((full_output[header_end] == '\r') ? 4 : 2));
} else {
    // No headers found, treat all as body
    body = full_output;
}

// (Optional) parse Content-Type or other headers if needed

// Send body only (or repackage with your own HTTP headers)
output << body;


        close(cgi_output[0]);
        waitpid(pid, NULL, 0);

        std::string out_str = output.str();
        send_response(client,ssl, "200 OK", "text/html", out_str);
    }
}

void redirect_to_https(int client, const std::string& host, const std::string& path, int https_port) {
    std::ostringstream response;
    response << "HTTP/1.1 301 Moved Permanently\r\n"
             << "Location: https://" << host << ":" << https_port << path << "\r\n"
             << "Connection: close\r\n"
             << "Content-Length: 0\r\n\r\n";
    send(client, response.str().c_str(), response.str().size(), 0);
    close(client);
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

void handle_client(int client,SSL* ssl = nullptr) {
    char buffer[BUFFER_SIZE];
    int bytes = ssl ? SSL_read(ssl, buffer, BUFFER_SIZE) : recv(client, buffer, BUFFER_SIZE, 0);
    //std::cout << "Received " << bytes << " bytes from client\n";
        if (bytes <= 0) {
        if (ssl) SSL_free(ssl);
        close(client);
        return;
    }

    std::string request(buffer);
    std::istringstream iss(request);
    std::string method, url, version;
    iss >> method >> url >> version;
    
        std::string content_type;
    int content_length = 0;
    std::string line;
    
    
    std::istringstream request2(buffer); // this must be valid


    std::string host = "localhost";  // default fallback
while (std::getline(request2, line) && line != "\r") {
    if (line.find("Host:") != std::string::npos)
        host = line.substr(line.find(":") + 2);
    //host = host.substr(0, host.find(":"));
    // ... other header parsing
}
std::string root = WEBROOT;
if (vhosts.count(host)) {
    root = vhosts[host];
}

    std::string query_string;
    size_t qs_pos = url.find('?');
    if (qs_pos != std::string::npos) {
        query_string = url.substr(qs_pos + 1);
        url = url.substr(0, qs_pos);
    }
    
    std::string filepath = root + url;
   // if (filepath.back() == '/') filepath += "index.html";
   
// If SSL is not used, redirect to HTTPS
if (!ssl) {
   // redirect_to_https(client, host, filepath,HTTPS_PORT);
  //  return;
}
   if (url == "/favicon.ico") {
   // send_response(client,ssl, "204 No Content", "image/x-icon", "");
   //     if (ssl) SSL_shutdown(ssl), SSL_free(ssl);
  //  close(client);
  //  return;
}
// If it's a directory, try to find index files
struct stat path_stat;
if (stat(filepath.c_str(), &path_stat) == 0 && S_ISDIR(path_stat.st_mode)) {
    if (filepath.back() != '/')
        filepath += '/';  // make sure path ends in '/'

    std::vector<std::string> index_files = {"index.php", "index.html"};

    for (const auto& fname : index_files) {
        std::string index_path = filepath + fname;
        if (stat(index_path.c_str(), &path_stat) == 0) {
            filepath = index_path;
            break;
        }
    }
}

    struct stat st;
    if (stat(filepath.c_str(), &st) == -1) {
        send_response(client,ssl, "404 Not Found", "text/plain", "404 Not Found");
        log("404 for " + filepath);
    if (ssl) SSL_shutdown(ssl), SSL_free(ssl);
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
   
   
    if (ends_with(".php",filepath)) {
        handle_php_cgi(client,ssl, filepath, query_string, method, post_data);
    } else if (url == "/upload" && method == "POST") {
        size_t bpos = request.find("boundary=");
        std::string boundary = (bpos != std::string::npos) ? "--" + request.substr(bpos + 9, request.find("\r\n", bpos) - bpos - 9) : "";
        std::string filename = save_uploaded_file(post_data, boundary);
        send_response(client,ssl, "200 OK", "text/plain", "File uploaded: " + filename);
    } else {
        std::ifstream file(filepath, std::ios::binary);
        std::ostringstream oss;
        oss << file.rdbuf();
        send_response(client,ssl, "200 OK", get_mime_type(filepath), oss.str());
    }
    
    if (ssl) SSL_shutdown(ssl), SSL_free(ssl);
    close(client);
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

int main(int argc, char* argv[]) {
	// Parse command-line arguments
    std::string CertS = "cert.pem";
    std::string KeyS = "key.pem";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--http" || arg == "-h") && i + 1 < argc) {
            HTTP_PORT = std::stoi(argv[++i]);
        } else if ((arg == "--https" || arg == "-s") && i + 1 < argc) {
            HTTPS_PORT = std::stoi(argv[++i]);
           } else if ((arg == "--cert" || arg == "-c") && i + 1 < argc) {
                        CertS = std::stoi(argv[++i]);
                       } else if ((arg == "--key" || arg == "-k") && i + 1 < argc) {
                                    KeyS = std::stoi(argv[++i]);
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [--http <port>] [--https <port>]\n";
            return 0;
        }
    }
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

    if (SSL_CTX_use_certificate_file(ctx, CertS.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KeyS.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int http_sock = create_listening_socket(HTTP_PORT);
    int https_sock;
    if(https_enabled){
    		https_sock = create_listening_socket(HTTPS_PORT) ;  
    		
    		 }else{    		https_sock =-1 ;  
    		}
    		 
    		 
        fd_set readfds;
    int maxfd = std::max(http_sock, https_sock) + 1;

  //  log("HTTPS Server started on port " + std::to_string(PORT));
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
            std::thread(handle_client, client, nullptr).detach();
           
        }

        if (FD_ISSET(https_sock, &readfds)) {
            int client2 = accept(https_sock, nullptr, nullptr);
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client2);
           
if (SSL_accept(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    close(client2);
        https_enabled =0;
    continue;
} else {
                std::thread(handle_client, client2, ssl).detach();
          }}
    }

close(http_sock);
    close(https_sock);
    SSL_CTX_free(ctx);
    return 0;
}
