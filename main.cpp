#include <SFML/Network.hpp>
#include <arpa/inet.h>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

class ScanPort
{
  public:
    ScanPort(const std::string& address, int start, int end) : m_address{address}, m_start{start}, m_end{end} {
        if (m_end < m_start || m_end > 65535) {
            throw std::runtime_error("Error: input error");
        }
        std::cout << "Scanning " << m_address << "...\n";
    }
    void display() {
        for (int port = m_start; port <= m_end; ++port) {
            if (scan_port(port)) {
                std::cout << "OPEN." << std::endl;
                open_ports.insert(port);
            } else {
                std::cout << "CLOSED" << std::endl;
            }
        }
    }

    void displayOpenPorts() {
        if (open_ports.empty()) {
            std::cout << "No open ports found.\n";
        } else {
            std::cout << '\n' << open_ports.size() << " open port(s):\n";
            for (auto port : open_ports) {
                std::cout << "Port " << port << ": OPEN\n";
            }
        }
    }

  private:
    std::set<int> open_ports;
    std::string   m_address;
    int           m_start;
    int           m_end;

    bool port_is_open(int port) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            throw std::runtime_error("socket() error");
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        int res         = inet_pton(AF_INET, m_address.c_str(), &addr.sin_addr);
        if (res != 1) {
            close(fd);
            throw std::runtime_error("inet_pton() error");
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            close(fd);
            throw std::runtime_error("fcntl() error");
        }

        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
            if (errno != EINPROGRESS) {
                close(fd);
                return false;
            }

            fd_set set;
            FD_ZERO(&set);
            FD_SET(fd, &set);

            struct timeval tv;
            tv.tv_sec  = 1;
            tv.tv_usec = 0;

            if (select(fd + 1, NULL, &set, NULL, &tv) <= 0) {
                close(fd);
                return false;
            }

            int       optval;
            socklen_t optlen = sizeof(optval);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1 || optval != 0) {
                close(fd);
                return false;
            }
        }

        if (fcntl(fd, F_SETFL, flags) == -1) {
            close(fd);
            throw std::runtime_error("fcntl() error");
        }

        close(fd);
        return true;
    }

    /*
    static bool port_is_open(const std::string& address, int port) {
        return (sf::TcpSocket().connect(address, port) == sf::Socket::Done);
    }
    */

    bool scan_port(int port) {
        std::cout << "Port " << port << ": ";
        try {
            if (port_is_open(port)) {
               return true;
            } else {
                return false;
            }
        } catch (const std::exception& ex) {
            std::cout << "ERROR (" << ex.what() << ")" << std::endl;
            return false;
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "USAGE: " << argv[0] << " <HOST> <DIAPOSON>" << std::endl;
        return 1;
    }
    try {
        ScanPort scan(argv[1], std::atoi(argv[2]), std::atoi(argv[3]));
        scan.display();
        scan.displayOpenPorts();
    } catch (const std::exception& e) {
        std::cout << e.what() << "\n";
    }
    return 0;
}
