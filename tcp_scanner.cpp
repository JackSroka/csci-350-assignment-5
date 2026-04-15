#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

static const string HOSTNAME = "blitz.cs.niu.edu";
static const int START_PORT = 9000;
static const int END_PORT = 9100;
static const int GROUP_NUMBER = 7;
static const int CONNECT_TIMEOUT_SEC = 2;

// RC4 implementation
vector<unsigned char> rc4(const vector<unsigned char>& key, const vector<unsigned char>& data) {
    vector<unsigned char> S(256);
    for (int i = 0; i < 256; i++) S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key.size()]) % 256;
        swap(S[i], S[j]);
    }

    vector<unsigned char> output(data.size());
    int i = 0;
    j = 0;

    for (size_t n = 0; n < data.size(); n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(S[i], S[j]);
        unsigned char K = S[(S[i] + S[j]) % 256];
        output[n] = data[n] ^ K;
    }

    return output;
}

bool starts_with_error(const string& s) {
    return s.rfind("Error", 0) == 0;
}

string bytes_to_hex(const vector<unsigned char>& data) {
    ostringstream oss;
    for (unsigned char b : data) {
        oss << hex << setw(2) << setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

bool receive_all(int sockfd, vector<unsigned char>& buffer) {
    unsigned char temp[4096];

    while (true) {
        ssize_t n = recv(sockfd, temp, sizeof(temp), 0);
        if (n > 0) {
            buffer.insert(buffer.end(), temp, temp + n);
        } else if (n == 0) {
            return !buffer.empty();
        } else {
            if (errno == EINTR) continue;
            return !buffer.empty();
        }
    }
}

int connect_to_port(const string& ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    timeval tv{};
    tv.tv_sec = CONNECT_TIMEOUT_SEC;
    tv.tv_usec = 0;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int main() {
    string target_ip = "10.158.56.43"; // NIU local IP

    cout << "Scanning TCP ports " << START_PORT << "-" << END_PORT
         << " on " << HOSTNAME << " (" << target_ip << ")" << endl;

    string query = "group " + to_string(GROUP_NUMBER);

    for (int port = START_PORT; port <= END_PORT; port++) {
        int sockfd = connect_to_port(target_ip, port);
        if (sockfd < 0) continue;

        cout << "\nConnected to port " << port << endl;

        if (send(sockfd, query.c_str(), query.size(), 0) < 0) {
            cerr << "Send failed on port " << port << endl;
            close(sockfd);
            continue;
        }

        vector<unsigned char> response_bytes;
        bool got_data = receive_all(sockfd, response_bytes);
        close(sockfd);

        if (!got_data || response_bytes.empty()) {
            cout << "No response on port " << port << endl;
            continue;
        }

        string response_text(response_bytes.begin(), response_bytes.end());

        if (starts_with_error(response_text)) {
            cout << "Error from server on port " << port << ": "
                 << response_text << endl;
            continue;
        }

        if (response_bytes.size() < 16) {
            cout << "Invalid response (too short) on port " << port << endl;
            continue;
        }

        vector<unsigned char> key(response_bytes.begin(), response_bytes.begin() + 16);
        vector<unsigned char> ciphertext(response_bytes.begin() + 16, response_bytes.end());

        vector<unsigned char> plaintext = rc4(key, ciphertext);
        string decrypted(plaintext.begin(), plaintext.end());

        cout << "\n=== SUCCESS ===" << endl;
        cout << "Port: " << port << endl;
        cout << "Key (hex): " << bytes_to_hex(key) << endl;
        cout << "Decrypted message: " << decrypted << endl;

        return 0;
    }

    cout << "\nNo valid TCP response found." << endl;
    return 1;
}
