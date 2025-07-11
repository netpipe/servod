// Decentralized Web Cache + Peer Server + HTTP Access
// Features: serve from ZIP, CGI PHP support, peer lookup/fetch, cache rotation, optional file archive split, user uploads, HTTP access
// Dependencies: zlib, SQLite3, OpenSSL, system zip/unzip, php-cgi

#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <sqlite3.h>
#include <cstdlib>
#include <map>
#include <vector>
#include <thread>
#include <regex>
#include <chrono>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

namespace fs = std::filesystem;

const size_t MAX_SITE_SIZE = 10 * 1024 * 1024;
const int ZIP_EXPIRY_DAYS = 7;
const std::string CACHE_DIR = "cache/";
const std::string DB_PATH = "db/cache.db";
const std::string UPLOAD_DIR = "uploads/";
const int PEER_PORT = 9000;
const int HTTP_PORT = 8080;
std::vector<std::string> knownPeers = {"127.0.0.1:9000"};

std::map<std::string, std::string> hashIndex;


std::string sha256(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount()) {
        SHA256_Update(&ctx, buf, file.gcount());
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    std::ostringstream result;
    for (unsigned char c : hash)
        result << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return result.str();
}

bool zip_file(const std::string& inputPath, const std::string& outputZip) {
    std::ostringstream cmd;
    cmd << "zip -j -q " << outputZip << " " << inputPath;
    return std::system(cmd.str().c_str()) == 0;
}

std::string extract_from_zip(const std::string& zipPath, const std::string& fileName) {
    std::string outFile = "/tmp/" + fs::path(fileName).filename().string();
    std::ostringstream cmd;
    cmd << "unzip -p " << zipPath << " " << fileName << " > " << outFile;
    int res = std::system(cmd.str().c_str());
    return (res == 0 && fs::exists(outFile)) ? outFile : "";
}

void run_php_cgi(const std::string& scriptPath) {
    std::ostringstream cmd;
    cmd << "REDIRECT_STATUS=1 SCRIPT_FILENAME=" << scriptPath << " php-cgi";
    FILE* pipe = popen(cmd.str().c_str(), "r");
    if (!pipe) {
        std::cerr << "[ERROR] Failed to run php-cgi\n";
        return;
    }
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::cout << buffer;
    }
    pclose(pipe);
}

void log_to_db(const std::string& path, const std::string& hash, const std::string& zipfile) {
    sqlite3* db;
    sqlite3_open(DB_PATH.c_str(), &db);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS cache_log (id INTEGER PRIMARY KEY, path TEXT, hash TEXT, zipfile TEXT, timestamp TEXT);", nullptr, nullptr, nullptr);
    std::ostringstream ts;
    std::time_t now = std::time(nullptr);
    ts << std::put_time(std::gmtime(&now), "%Y-%m-%dT%H:%M:%SZ");
    std::ostringstream sql;
    sql << "INSERT INTO cache_log (path, hash, zipfile, timestamp) VALUES (\""
        << path << "\", \"" << hash << "\", \"" << zipfile << "\", \"" << ts.str() << "\");";
    sqlite3_exec(db, sql.str().c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
    hashIndex[path] = hash;
}

void archive_file_if_needed(const std::string& filepath) {
    if (!fs::exists(filepath)) return;
    std::uintmax_t size = fs::file_size(filepath);
    if (size > MAX_SITE_SIZE) {
        std::cout << "[WARN] Skipping " << filepath << ": exceeds size limit.\n";
        return;
    }
    std::string hash = sha256(filepath);
    std::string zipname = CACHE_DIR + hash + ".zip";
    if (fs::exists(zipname)) {
        std::cout << "[INFO] Already cached: " << zipname << "\n";
        return;
    }
    fs::create_directories(CACHE_DIR);
    if (zip_file(filepath, zipname)) {
        log_to_db(filepath, hash, zipname);
        std::cout << "[LOG] Archived + hashed: " << filepath << "\n";
    } else {
        std::cout << "[ERROR] Failed to zip: " << filepath << "\n";
    }
}

std::string get_hash_for_path(const std::string& reqPath) {
    return hashIndex.count(reqPath) ? hashIndex[reqPath] : "";
}

bool query_peers_for_zip(const std::string& hash) {
    for (const auto& peer : knownPeers) {
        std::string cmd = "curl -s http://" + peer + "/lookup?hash=" + hash;
        if (std::system(cmd.c_str()) == 0) {
            std::cout << "[PEER] Found " << hash << " on " << peer << "\n";
            return true;
        }
    }
    return false;
}

void cleanup_old_zips(int daysOld = ZIP_EXPIRY_DAYS) {
    for (auto& file : fs::directory_iterator(CACHE_DIR)) {
        auto ftime = fs::last_write_time(file);
        auto age = std::chrono::duration_cast<std::chrono::hours>(std::chrono::system_clock::now() - ftime).count() / 24;
        if (age > daysOld) {
            std::cout << "[CLEANUP] Deleting " << file.path() << " (age: " << age << " days)\n";
            fs::remove(file.path());
        }
    }
}

void archive_user_upload(const std::string& filepath) {
    fs::create_directories(UPLOAD_DIR);
    std::string hash = sha256(filepath);
    std::string zipname = UPLOAD_DIR + hash + ".zip";
    if (zip_file(filepath, zipname)) {
        std::cout << "[UPLOAD] Archived: " << filepath << " to " << zipname << "\n";
    }
}

void start_peer_server() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PEER_PORT);
    bind(server_fd, (sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);
    std::cout << "[PEER] Listening on port " << PEER_PORT << "\n";
    while (true) {
        int client = accept(server_fd, nullptr, nullptr);
        std::thread([client]() {
            char buf[1024];
            int n = read(client, buf, sizeof(buf) - 1);
            buf[n] = 0;
            std::string req(buf);
            std::smatch match;
            if (std::regex_search(req, match, std::regex("GET /lookup\\?hash=([a-f0-9]+)"))) {
                std::string hash = match[1];
                std::string zipfile = CACHE_DIR + hash + ".zip";
                if (fs::exists(zipfile)) {
                    std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nFOUND";
                    send(client, resp.c_str(), resp.size(), 0);
                } else {
                    std::string resp = "HTTP/1.1 404 Not Found\r\n\r\n";
                    send(client, resp.c_str(), resp.size(), 0);
                }
            }
            close(client);
        }).detach();
    }
}

void start_http_server() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(HTTP_PORT);
    bind(server_fd, (sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);
    std::cout << "[HTTP] Listening on port " << HTTP_PORT << "\n";

    while (true) {
        int client = accept(server_fd, nullptr, nullptr);
        std::thread([client]() {
            char buf[2048];
            int n = read(client, buf, sizeof(buf) - 1);
            buf[n] = 0;
            std::string req(buf);
            std::smatch match;
            std::regex getRegex("GET \\/(\\w+)\\/(.*) HTTP");

            if (std::regex_search(req, match, getRegex)) {
                std::string site = match[1];
                std::string file = match[2].empty() ? "index.php" : match[2];
                std::string hash = sha256(site);
                std::string zipfile = CACHE_DIR + hash + ".zip";

                if (!fs::exists(zipfile)) {
                    if (!query_peers_for_zip(hash)) {
                        std::string notfound = "HTTP/1.1 404 Not Found\r\n\r\nSite Not Found";
                        send(client, notfound.c_str(), notfound.size(), 0);
                        close(client);
                        return;
                    }
                }

                std::string extracted = extract_from_zip(zipfile, file);
                if (extracted.empty()) {
                    std::string notfound = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
                    send(client, notfound.c_str(), notfound.size(), 0);
                } else {
                    if (file.ends_with(".php")) {
                        dup2(client, STDOUT_FILENO);
                        run_php_cgi(extracted);
                    } else {
                        std::ifstream in(extracted);
                        std::ostringstream ss;
                        ss << "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" << in.rdbuf();
                        std::string out = ss.str();
                        send(client, out.c_str(), out.size(), 0);
                    }
                }
            } else {
                std::string bad = "HTTP/1.1 400 Bad Request\r\n\r\n";
                send(client, bad.c_str(), bad.size(), 0);
            }
            close(client);
        }).detach();
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: archive <path-to-html-or-site-root>\n";
        return 1;
    }
    std::thread peerThread(start_peer_server);
    std::thread httpThread(start_http_server);

    std::string target = argv[1];
    if (fs::is_directory(target)) {
        for (auto& file : fs::recursive_directory_iterator(target)) {
            if (fs::is_regular_file(file)) {
                archive_file_if_needed(file.path().string());
            }
        }
    } else {
        archive_file_if_needed(target);
    }
    cleanup_old_zips();
    archive_user_upload("user_uploads/form_data.txt");

    peerThread.join();
    httpThread.join();
    return 0;
}
