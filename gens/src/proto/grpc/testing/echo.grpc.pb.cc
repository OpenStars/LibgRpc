// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: src/proto/grpc/testing/echo.proto

#include "src/proto/grpc/testing/echo.pb.h"
#include "src/proto/grpc/testing/echo.grpc.pb.h"

#include <grpc++/impl/codegen/async_stream.h>
#include <grpc++/impl/codegen/async_unary_call.h>
#include <grpc++/impl/codegen/channel_interface.h>
#include <grpc++/impl/codegen/client_unary_call.h>
#include <grpc++/impl/codegen/method_handler_impl.h>
#include <grpc++/impl/codegen/rpc_service_method.h>
#include <grpc++/impl/codegen/service_type.h>
#include <grpc++/impl/codegen/sync_stream.h>
namespace grpc {
namespace testing {

static const char* EchoTestService_method_names[] = {
  "/grpc.testing.EchoTestService/Echo",
  "/grpc.testing.EchoTestService/RequestStream",
  "/grpc.testing.EchoTestService/ResponseStream",
  "/grpc.testing.EchoTestService/BidiStream",
  "/grpc.testing.EchoTestService/Unimplemented",
};

std::unique_ptr< EchoTestService::Stub> EchoTestService::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  std::unique_ptr< EchoTestService::Stub> stub(new EchoTestService::Stub(channel));
  return stub;
}

EchoTestService::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_Echo_(EchoTestService_method_names[0], ::grpc::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_RequestStream_(EchoTestService_method_names[1], ::grpc::RpcMethod::CLIENT_STREAMING, channel)
  , rpcmethod_ResponseStream_(EchoTestService_method_names[2], ::grpc::RpcMethod::SERVER_STREAMING, channel)
  , rpcmethod_BidiStream_(EchoTestService_method_names[3], ::grpc::RpcMethod::BIDI_STREAMING, channel)
  , rpcmethod_Unimplemented_(EchoTestService_method_names[4], ::grpc::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status EchoTestService::Stub::Echo(::grpc::ClientContext* context, const ::grpc::testing::EchoRequest& request, ::grpc::testing::EchoResponse* response) {
  return ::grpc::BlockingUnaryCall(channel_.get(), rpcmethod_Echo_, context, request, response);
}

::grpc::ClientAsyncResponseReader< ::grpc::testing::EchoResponse>* EchoTestService::Stub::AsyncEchoRaw(::grpc::ClientContext* context, const ::grpc::testing::EchoRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::ClientAsyncResponseReader< ::grpc::testing::EchoResponse>::Create(channel_.get(), cq, rpcmethod_Echo_, context, request);
}

::grpc::ClientWriter< ::grpc::testing::EchoRequest>* EchoTestService::Stub::RequestStreamRaw(::grpc::ClientContext* context, ::grpc::testing::EchoResponse* response) {
  return new ::grpc::ClientWriter< ::grpc::testing::EchoRequest>(channel_.get(), rpcmethod_RequestStream_, context, response);
}

::grpc::ClientAsyncWriter< ::grpc::testing::EchoRequest>* EchoTestService::Stub::AsyncRequestStreamRaw(::grpc::ClientContext* context, ::grpc::testing::EchoResponse* response, ::grpc::CompletionQueue* cq, void* tag) {
  return ::grpc::ClientAsyncWriter< ::grpc::testing::EchoRequest>::Create(channel_.get(), cq, rpcmethod_RequestStream_, context, response, tag);
}

::grpc::ClientReader< ::grpc::testing::EchoResponse>* EchoTestService::Stub::ResponseStreamRaw(::grpc::ClientContext* context, const ::grpc::testing::EchoRequest& request) {
  return new ::grpc::ClientReader< ::grpc::testing::EchoResponse>(channel_.get(), rpcmethod_ResponseStream_, context, request);
}

::grpc::ClientAsyncReader< ::grpc::testing::EchoResponse>* EchoTestService::Stub::AsyncResponseStreamRaw(::grpc::ClientContext* context, const ::grpc::testing::EchoRequest& request, ::grpc::CompletionQueue* cq, void* tag) {
  return ::grpc::ClientAsyncReader< ::grpc::testing::EchoResponse>::Create(channel_.get(), cq, rpcmethod_ResponseStream_, context, request, tag);
}

::grpc::ClientReaderWriter< ::grpc::testing::EchoRequest, ::grpc::testing::EchoResponse>* EchoTestService::Stub::BidiStreamRaw(::grpc::ClientContext* context) {
  return new ::grpc::ClientReaderWriter< ::grpc::testing::EchoRequest, ::grpc::testing::EchoResponse>(channel_.get(), rpcmethod_BidiStream_, context);
}

::grpc::ClientAsyncReaderWriter< ::grpc::testing::EchoRequest, ::grpc::testing::EchoResponse>* EchoTestService::Stub::AsyncBidiStreamRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq, void* tag) {
  return ::grpc::ClientAsyncReaderWriter< ::grpc::testing::EchoRequest, ::grpc::testing::EchoResponse>::Create(channel_.get(), cq, rpcmethod_BidiStream_, context, tag);
}

::grpc::Status EchoTestService::Stub::Unimplemented(::grpc::ClientContext* context, const ::grpc::testing::EchoRequest& request, ::grpc::testing::EchoResponse* response) {
  return ::grpc::BlockingUnaryCall(channel_.get(), rpcmethod_Unimplemented_, context, request, response);
}

::grpc::ClientAsyncResponseReader< ::grpc::testing::EchoResponse>* EchoTestService::Stub::AsyncUnimplementedRaw(::grpc::ClientContext* context, const ::grpc::testing::EchoRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::ClientAsyncResponseReader< ::grpc::testing::EchoResponse>::Create(channel_.get(), cq, rpcmethod_Unimplemented_, context, request);
}

EchoTestService::Service::Service() {
  AddMethod(new ::grpc::RpcServiceMethod(
      EchoTestService_method_names[0],
      ::grpc::RpcMethod::NORMAL_RPC,
      new ::grpc::RpcMethodHandler< EchoTestService::Service, ::grpc::testing::EchoRequest, ::grpc::testing::EchoResponse>(
          std::mem_fn(&EchoTestService::Service::Echo), this)));
  AddMethod(new ::grpc::RpcServiceMethod(
      EchoTestService_method_names[1],
      ::grpc::RpcMethod::CLIENT_STREAMING,
      new ::grpc::ClientStreamingHandler< EchoTestService::Service, ::grpc::testing::EchoRequest, ::grpc::testing::EchoResponse>(
          std::mem_fn(&EchoTestService::Service::RequestStream), this)));
  AddMethod(new ::grpc::RpcServiceMethod(
      EchoTestService_method_names[2],
      ::grpc::RpcMethod::SERVER_STREAMING,
      new ::grpc::ServerStreamingHandler< EchoTestService::Service, ::grpc::testing::EchoRequest, ::grpc::testing::EchoResponse>(
          std::mem_fn(&EchoTestService::Service::ResponseStream), this)));
  AddMethod(new ::grpc::RpcServiceMethod(
      EchoTestService_method_names[3],
      ::grpc::RpcMethod::BIDI_STREAMING,
      new ::grpc::BidiStreamingHandler< EchoTestService::Service, ::grpc::testing::EchoRequest, ::grpc::testing::EchoResponse>(
          std::mem_fn(&EchoTestService::Service::BidiStream), this)));
  AddMethod(new ::grpc::RpcServiceMethod(
      EchoTestService_method_names[4],
      ::grpc::RpcMethod::NORMAL_RPC,
      new ::grpc::RpcMethodHandler< EchoTestService::Service, ::grpc::testing::EchoRequest, ::grpc::testing::EchoResponse>(
          std::mem_fn(&EchoTestService::Service::Unimplemented), this)));
}

EchoTestService::Service::~Service() {
}

::grpc::Status EchoTestService::Service::Echo(::grpc::ServerContext* context, const ::grpc::testing::EchoRequest* request, ::grpc::testing::EchoResponse* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status EchoTestService::Service::RequestStream(::grpc::ServerContext* context, ::grpc::ServerReader< ::grpc::testing::EchoRequest>* reader, ::grpc::testing::EchoResponse* response) {
  (void) context;
  (void) reader;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status EchoTestService::Service::ResponseStream(::grpc::ServerContext* context, const ::grpc::testing::EchoRequest* request, ::grpc::ServerWriter< ::grpc::testing::EchoResponse>* writer) {
  (void) context;
  (void) request;
  (void) writer;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status EchoTestService::Service::BidiStream(::grpc::ServerContext* context, ::grpc::ServerReaderWriter< ::grpc::testing::EchoResponse, ::grpc::testing::EchoRequest>* stream) {
  (void) context;
  (void) stream;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status EchoTestService::Service::Unimplemented(::grpc::ServerContext* context, const ::grpc::testing::EchoRequest* request, ::grpc::testing::EchoResponse* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


static const char* UnimplementedEchoService_method_names[] = {
  "/grpc.testing.UnimplementedEchoService/Unimplemented",
};

std::unique_ptr< UnimplementedEchoService::Stub> UnimplementedEchoService::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  std::unique_ptr< UnimplementedEchoService::Stub> stub(new UnimplementedEchoService::Stub(channel));
  return stub;
}

UnimplementedEchoService::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_Unimplemented_(UnimplementedEchoService_method_names[0], ::grpc::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status UnimplementedEchoService::Stub::Unimplemented(::grpc::ClientContext* context, const ::grpc::testing::EchoRequest& request, ::grpc::testing::EchoResponse* response) {
  return ::grpc::BlockingUnaryCall(channel_.get(), rpcmethod_Unimplemented_, context, request, response);
}

::grpc::ClientAsyncResponseReader< ::grpc::testing::EchoResponse>* UnimplementedEchoService::Stub::AsyncUnimplementedRaw(::grpc::ClientContext* context, const ::grpc::testing::EchoRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::ClientAsyncResponseReader< ::grpc::testing::EchoResponse>::Create(channel_.get(), cq, rpcmethod_Unimplemented_, context, request);
}

UnimplementedEchoService::Service::Service() {
  AddMethod(new ::grpc::RpcServiceMethod(
      UnimplementedEchoService_method_names[0],
      ::grpc::RpcMethod::NORMAL_RPC,
      new ::grpc::RpcMethodHandler< UnimplementedEchoService::Service, ::grpc::testing::EchoRequest, ::grpc::testing::EchoResponse>(
          std::mem_fn(&UnimplementedEchoService::Service::Unimplemented), this)));
}

UnimplementedEchoService::Service::~Service() {
}

::grpc::Status UnimplementedEchoService::Service::Unimplemented(::grpc::ServerContext* context, const ::grpc::testing::EchoRequest* request, ::grpc::testing::EchoResponse* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


std::unique_ptr< NoRpcService::Stub> NoRpcService::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  std::unique_ptr< NoRpcService::Stub> stub(new NoRpcService::Stub(channel));
  return stub;
}

NoRpcService::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel){}

NoRpcService::Service::Service() {
}

NoRpcService::Service::~Service() {
}


}  // namespace grpc
}  // namespace testing

