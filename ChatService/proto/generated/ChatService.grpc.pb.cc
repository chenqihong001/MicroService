// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: ChatService.proto

#include "ChatService.pb.h"
#include "ChatService.grpc.pb.h"

#include <functional>
#include <grpcpp/support/async_stream.h>
#include <grpcpp/support/async_unary_call.h>
#include <grpcpp/impl/channel_interface.h>
#include <grpcpp/impl/client_unary_call.h>
#include <grpcpp/support/client_callback.h>
#include <grpcpp/support/message_allocator.h>
#include <grpcpp/support/method_handler.h>
#include <grpcpp/impl/rpc_service_method.h>
#include <grpcpp/support/server_callback.h>
#include <grpcpp/impl/server_callback_handlers.h>
#include <grpcpp/server_context.h>
#include <grpcpp/impl/service_type.h>
#include <grpcpp/support/sync_stream.h>
namespace chat {

static const char* ChatService_method_names[] = {
  "/chat.ChatService/SendMessage",
  "/chat.ChatService/ReceiveMessages",
};

std::unique_ptr< ChatService::Stub> ChatService::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< ChatService::Stub> stub(new ChatService::Stub(channel, options));
  return stub;
}

ChatService::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options)
  : channel_(channel), rpcmethod_SendMessage_(ChatService_method_names[0], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_ReceiveMessages_(ChatService_method_names[1], options.suffix_for_stats(),::grpc::internal::RpcMethod::SERVER_STREAMING, channel)
  {}

::grpc::Status ChatService::Stub::SendMessage(::grpc::ClientContext* context, const ::chat::ChatMessage& request, ::chat::ChatReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::ChatMessage, ::chat::ChatReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_SendMessage_, context, request, response);
}

void ChatService::Stub::async::SendMessage(::grpc::ClientContext* context, const ::chat::ChatMessage* request, ::chat::ChatReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::ChatMessage, ::chat::ChatReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_SendMessage_, context, request, response, std::move(f));
}

void ChatService::Stub::async::SendMessage(::grpc::ClientContext* context, const ::chat::ChatMessage* request, ::chat::ChatReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_SendMessage_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::ChatReply>* ChatService::Stub::PrepareAsyncSendMessageRaw(::grpc::ClientContext* context, const ::chat::ChatMessage& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::ChatReply, ::chat::ChatMessage, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_SendMessage_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::ChatReply>* ChatService::Stub::AsyncSendMessageRaw(::grpc::ClientContext* context, const ::chat::ChatMessage& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncSendMessageRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::ClientReader< ::chat::ChatMessage>* ChatService::Stub::ReceiveMessagesRaw(::grpc::ClientContext* context, const ::chat::User& request) {
  return ::grpc::internal::ClientReaderFactory< ::chat::ChatMessage>::Create(channel_.get(), rpcmethod_ReceiveMessages_, context, request);
}

void ChatService::Stub::async::ReceiveMessages(::grpc::ClientContext* context, const ::chat::User* request, ::grpc::ClientReadReactor< ::chat::ChatMessage>* reactor) {
  ::grpc::internal::ClientCallbackReaderFactory< ::chat::ChatMessage>::Create(stub_->channel_.get(), stub_->rpcmethod_ReceiveMessages_, context, request, reactor);
}

::grpc::ClientAsyncReader< ::chat::ChatMessage>* ChatService::Stub::AsyncReceiveMessagesRaw(::grpc::ClientContext* context, const ::chat::User& request, ::grpc::CompletionQueue* cq, void* tag) {
  return ::grpc::internal::ClientAsyncReaderFactory< ::chat::ChatMessage>::Create(channel_.get(), cq, rpcmethod_ReceiveMessages_, context, request, true, tag);
}

::grpc::ClientAsyncReader< ::chat::ChatMessage>* ChatService::Stub::PrepareAsyncReceiveMessagesRaw(::grpc::ClientContext* context, const ::chat::User& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncReaderFactory< ::chat::ChatMessage>::Create(channel_.get(), cq, rpcmethod_ReceiveMessages_, context, request, false, nullptr);
}

ChatService::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::ChatMessage, ::chat::ChatReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::ChatMessage* req,
             ::chat::ChatReply* resp) {
               return service->SendMessage(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[1],
      ::grpc::internal::RpcMethod::SERVER_STREAMING,
      new ::grpc::internal::ServerStreamingHandler< ChatService::Service, ::chat::User, ::chat::ChatMessage>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::User* req,
             ::grpc::ServerWriter<::chat::ChatMessage>* writer) {
               return service->ReceiveMessages(ctx, req, writer);
             }, this)));
}

ChatService::Service::~Service() {
}

::grpc::Status ChatService::Service::SendMessage(::grpc::ServerContext* context, const ::chat::ChatMessage* request, ::chat::ChatReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::ReceiveMessages(::grpc::ServerContext* context, const ::chat::User* request, ::grpc::ServerWriter< ::chat::ChatMessage>* writer) {
  (void) context;
  (void) request;
  (void) writer;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace chat
