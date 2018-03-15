/*
 * TLS echo server using BSD sockets
 * (C) 2014 Jack Lloyd
 *     2017 Falko Strenzke, cryptosource GmbH
 *
 * Botan and the TLS Test Tool are released under the Simplified BSD License (see license.txt)
 */

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_SOCKETS)

# include <exception>
# include <botan/tls_server.h>
# include <botan/hex.h>

# include <list>

# include <sys/types.h>
# include <sys/time.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <netdb.h>
# include <unistd.h>
# include <errno.h>
# include <fcntl.h>
# include <boost/timer/timer.hpp>
# include <boost/chrono.hpp>
# include <future>
# include <functional>
# include "util.h"

# if !defined(MSG_NOSIGNAL)
#  define MSG_NOSIGNAL 0
# endif

namespace {
  uint64_t string_to_u64bit(std::string const& str)
  {
    std::istringstream is(str);
    uint64_t result;
    is >> result;
    return result;
  }
}

namespace Botan_CLI {
  class TLS_Server;
  static TLS_Server* stc_server = nullptr;

  class TLS_Server final : public Command
  {
public:
    TLS_Server() : Command(
        "tls_server --test_main_dir= --test_case= --result_dir= --port=443 --timeout= --type=tcp --policy= --stay"){ }

    void run_instance(Botan::Credentials_Manager* creds) override
    {
      stc_server = this;
      std::string timeout_str        = get_arg_or("timeout", "2");
      const unsigned timeout_seconds = string_to_u64bit(timeout_str);
      auto timeout = std::chrono::seconds(timeout_seconds);

      const int port = get_arg_sz("port");
      const std::string transport = get_arg("type");

      if(timeout_seconds == 0)
      {
        m_use_timeout = false;
      }

      if(transport != "tcp" && transport != "udp")
        throw CLI_Usage_Error("Invalid transport type '" + transport + "' for TLS");

      const bool is_tcp = (transport == "tcp");

      std::unique_ptr<Botan::TLS::Policy> policy;
      const std::string policy_file = get_arg("policy");
      std::filebuf fb;
      if(policy_file.size() > 0)
      {
        std::ifstream policy_stream(policy_file);
        if(!policy_stream.good())
        {
          error_output() << "Failed reading policy file\n";
          return;
        }
        policy.reset(new Botan::TLS::Text_Policy(policy_stream));
      }

      if(!policy)
      {
        policy.reset(new Botan::TLS::Policy);
      }

      Botan::TLS::Session_Manager_In_Memory session_manager(rng()); // TODO sqlite3


      auto protocol_chooser = [](const std::vector<std::string>& protocols) -> std::string {
          for(size_t i = 0; i != protocols.size(); ++i)
          {
            std::cout << "Client offered protocol " << i << " = " << protocols[i] << std::endl;
          }
          return "";
        };

      output() << "Listening for new connections on " << transport << " port " << port << std::endl;

      int server_fd = make_server_socket(is_tcp, port);

      boost::timer::auto_cpu_timer timer;

      bool stay_up = flag_set("stay") ? true : false;
      do
      {
        try
        {
          std::packaged_task<int()> accept_task([&](){
            return accept(server_fd, nullptr, nullptr);
          });

          std::future<int> fut = accept_task.get_future();
          std::thread(std::move(accept_task)).detach();
          if(m_use_timeout)
          {
            if(fut.wait_for(timeout)
              == std::future_status::timeout)
            {
              throw timeout_exception_t("timeout during accept");
            }
          }
          fut.wait();
          int fd = fut.get();
          m_sock_fd = fd;

          using namespace std::placeholders;

          auto socket_write = is_tcp ? std::bind(&stream_socket_write, fd, _1, _2) :
            std::bind(&dgram_socket_write, fd, _1, _2);

          std::string s;
          std::list<std::string> pending_output;

          auto proc_fn = [&](const uint8_t input[], size_t input_len)
            {
              for(size_t i = 0; i != input_len; ++i)
              {
                const char c = static_cast<char>(input[i]);
                s += c;
                if(c == '\n')
                {
                  pending_output.push_back(s);
                  s.clear();
                }
              }
            };

          Botan::TLS::Server server(socket_write,
            proc_fn,
            std::bind(&TLS_Server::alert_received, this, _1, _2, _3),
            std::bind(&TLS_Server::handshake_complete, this, _1),
            session_manager,
            *creds,
            *policy,
            rng(),
            protocol_chooser,
            !is_tcp);

          while(!server.is_closed())
          {
            auto nanoseconds = boost::chrono::nanoseconds(timer.elapsed().user + timer.elapsed().system);
            auto seconds     = boost::chrono::duration_cast<boost::chrono::seconds>(nanoseconds);
            if(m_use_timeout && (seconds > boost::chrono::seconds(timeout_seconds)))
            {
              throw timeout_exception_t("timeout reached");
            }
            uint8_t buf[4 * 1024] = {0};


            std::packaged_task<ssize_t()> read_task([&](){
              return ::read(fd, buf, sizeof(buf));
            });

            std::future<ssize_t> rfut = read_task.get_future();
            std::thread(std::move(read_task)).detach();
            if(m_use_timeout)
            {
              if(rfut.wait_for(timeout)
                == std::future_status::timeout)
              {
                throw timeout_exception_t("timeout during read");
              }
            }
            rfut.wait();
            ssize_t got = rfut.get();

            m_handshake_begun = true;

            if(got == -1)
            {
              std::cout << "Error in socket read - " << strerror(errno) << std::endl;
              break;
            }

            if(got == 0)
            {
              std::cout << "EOF on socket" << std::endl;
              break;
            }

            server.received_data(buf, got);

            while(server.is_active() && !pending_output.empty())
            {
              std::string output = pending_output.front();
              pending_output.pop_front();
              server.send(output);

              if(output == "quit\n")
                server.close();
            }
          }

          if(is_tcp)
            ::close(fd);
        }
        catch(timeout_exception_t const& e)
        {
          throw e;
        }
        catch(std::exception const& e)
        {
          if(stay_up)
          {
            std::cout << "caught exeption (staying up): " << e.what() << std::endl;
          }
          else
          {
            throw e;
          }
        }
      } while(stay_up);
    } // run_instance

private:
    int make_server_socket(
      bool     is_tcp,
      uint16_t port
    )
    {
      const int type = is_tcp ? SOCK_STREAM : SOCK_DGRAM;

      int fd = ::socket(PF_INET, type, 0);

      if(fd == -1)
        throw CLI_Error("Unable to acquire socket");

      sockaddr_in socket_info;
      ::memset(&socket_info, 0, sizeof(socket_info));
      socket_info.sin_family = AF_INET;
      socket_info.sin_port   = htons(port);

      // FIXME: support limiting listeners
      socket_info.sin_addr.s_addr = INADDR_ANY;

      if(::bind(fd, reinterpret_cast<struct sockaddr*>(&socket_info), sizeof(struct sockaddr)) != 0)
      {
        ::close(fd);
        throw CLI_Error("server bind failed");
      }

      if(is_tcp)
      {
        if(::listen(fd, 100) != 0)
        {
          ::close(fd);
          throw CLI_Error("listen failed");
        }
      }

      return fd;
    } // make_server_socket

    bool handshake_complete(const Botan::TLS::Session& session)
    {
      std::cout << "Handshake complete, " << session.version().to_string()
                << " using " << session.ciphersuite().to_string() << std::endl;
      m_ciphersuite = session.ciphersuite().to_string();
      if(!session.session_id().empty())
        std::cout << "Session ID " << Botan::hex_encode(session.session_id()) << std::endl;

      if(!session.session_ticket().empty())
        std::cout << "Session ticket " << Botan::hex_encode(session.session_ticket()) << std::endl;
      m_handshake_completed = true;
      return true;
    }

    static void dgram_socket_write(
      int           sockfd,
      const uint8_t buf[],
      size_t        length
    )
    {
      ssize_t sent = ::send(sockfd, buf, length, MSG_NOSIGNAL);

      if(sent == -1)
        std::cout << "Error writing to socket - " << strerror(errno) << std::endl;
      else if(sent != static_cast<ssize_t>(length))
        std::cout << "Packet of length " << length << " truncated to " << sent << std::endl;
    }

    static void stream_socket_write(
      int           sockfd,
      const uint8_t buf[],
      size_t        length
    )
    {
      while(length)
      {
        ssize_t sent = ::send(sockfd, buf, length, MSG_NOSIGNAL);

        if(sent == -1)
        {
          if(errno == EINTR)
          {
            sent = 0;
          }
          else
          {
            uint8_t rec_buf[4096];
            ssize_t got = ::read(stc_server->m_sock_fd, rec_buf, sizeof(rec_buf));
            if(!stc_server->m_handshake_completed)
            {
              stc_server->m_rec_alert = try_parse_alert(buf, got);
            }

            throw CLI_Error("Socket write failed");
          }
        }

        buf    += sent;
        length -= sent;
      }
    }

    void alert_received(
      Botan::TLS::Alert alert,
      const uint8_t[],
      size_t
    )
    {
      std::cout << "Alert: " << alert.type_string() << std::endl;
      // m_rec_alerts.push_back(alert);
      m_rec_alert = std::unique_ptr<Botan::TLS::Alert>(new Botan::TLS::Alert(alert));
    }

    bool m_use_timeout = true;
    int m_sock_fd      = 0;
  };

  BOTAN_REGISTER_COMMAND("tls_server", TLS_Server);
}

#endif // if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_SOCKETS)
