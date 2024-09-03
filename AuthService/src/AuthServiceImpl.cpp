#include "AuthServiceImpl.h"
#include <fstream>
#include <chrono>

AuthServiceImpl::~AuthServiceImpl()
{
}

grpc::Status AuthServiceImpl::Register(grpc::ServerContext *context, const auth::RegisterRequest *request, auth::AuthResponse *response)
{
    const std::string &username = request->username();
    const std::string &password = request->password();

    // 查找用户操作
    if (userStore_.find(username) != userStore_.end())
    {
        response->set_message("User already exists"); // 用户已经存在
        return grpc::Status::OK;
    }

    // 注册用户操作
    userStore_[username] = password;
    response->set_message("User registered successfully"); // 用户注册成功
    return grpc::Status::OK;
}

grpc::Status AuthServiceImpl::Login(grpc::ServerContext *context, const auth::LoginRequest *request, auth::AuthResponse *response)
{
    const std::string &username = request->username();
    const std::string &password = request->password();

    if (userStore_.find(username) == userStore_.end() || userStore_[username] != password)
    {
        response->set_message("Invalid username or password"); // 用户名或密码错误
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Unauthenticated user");
    }
    // 验证成功
    auto token = GenerateJWT(username);        // 通过username 生成token
    response->set_token(token);                // 返回token
    response->set_message("Login successful"); // 登录成功
    // 查找用户操作
    return grpc::Status::OK;
}

grpc::Status AuthServiceImpl::ValidateToken(grpc::ServerContext *context, const auth::ValidateTokenRequest *request, auth::ValidateTokenResponse *response)
{
    const std::string &token = request->token();
    auto result = ValidateJWT(token);
    if (result.first) // 成功
    {
        response->set_is_valid(true);
        response->set_username(result.second);
        response->set_message("Token is valid");
    }
    else
    {
        response->set_is_valid(false);
        response->set_message("Token is invalid");
    }
    return grpc::Status::OK;
}

grpc::Status AuthServiceImpl::Logout(grpc::ServerContext *context, const auth::LogoutRequest *request, auth::LogoutResponse *response)
{
    return grpc::Status();
}

std::string AuthServiceImpl::GenerateJWT(const std::string &username)
{
    auto token = jwt::create()
                     .set_issuer("auth_service")
                     .set_type("JWT")
                     .set_audience("chat_service")
                     .set_subject(username)
                     .set_issued_at(std::chrono::system_clock::now())
                     .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds(3600))
                     .sign(jwt::algorithm::rs256{"", loadPrivateKey("/root/microservice/AuthService/secret_key/private_key.pem")});
    return token;
}

std::pair<bool, std::string> AuthServiceImpl::ValidateJWT(const std::string &token)
{
    try
    {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs256{loadPublicKey("/root/microservice/AuthService/secret_key/public_key.pem")})
                            .with_issuer("auth_service");
        verifier.verify(decoded);
        return {true, decoded.get_subject()}; // 获取之前设置的username
    }
    catch (const std::exception &e)
    {
        std::cerr << "Token validation failed" << e.what() << std::endl;
        return std::pair<bool, std::string>(false, "");
    }
}

std::string AuthServiceImpl::loadPrivateKey(const std::string &filename)
{
    std::ifstream keyFile(filename, std::ios::binary);

    if (!keyFile.is_open())
    {
        throw std::runtime_error("无法打开私钥文件: " + filename);
    }
    std::stringstream buffer;
    buffer << keyFile.rdbuf();
    return buffer.str();
}

std::string AuthServiceImpl::loadPublicKey(const std::string &filename)
{
    std::ifstream keyFile(filename, std::ios::binary);

    if (!keyFile.is_open())
    {
        throw std::runtime_error("无法打开公钥文件: " + filename);
    }
    std::stringstream buffer;
    buffer << keyFile.rdbuf();
    return buffer.str();
}
