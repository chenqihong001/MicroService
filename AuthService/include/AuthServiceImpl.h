#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include "AuthService.grpc.pb.h"
#include <grpcpp/grpcpp.h>
#include <jwt-cpp/jwt.h>

class AuthServiceImpl final : public auth::AuthService::Service
{
public:
    AuthServiceImpl();
    ~AuthServiceImpl();
    grpc::Status Register(grpc::ServerContext *context, const auth::RegisterRequest *request, auth::AuthResponse *response) override;
    grpc::Status Login(grpc::ServerContext *context, const auth::LoginRequest *request, auth::AuthResponse *response) override;
    grpc::Status Logout(grpc::ServerContext *context, const auth::LogoutRequest *request, auth::LogoutResponse *response) override;
    grpc::Status ValidateToken(grpc::ServerContext *context, const auth::ValidateTokenRequest *request, auth::ValidateTokenResponse *response) override;

public:
    std::string GenerateJWT(const std::string &username);
    std::pair<bool, std::string> ValidateJWT(const std::string &token);
    std::string loadPrivateKey(const std::string &filename);
    std::string loadPublicKey(const std::string &filename);

    std::unordered_map<std::string, std::string> userStore_; // 用户信息存储
};
// 回调式
// 异步式