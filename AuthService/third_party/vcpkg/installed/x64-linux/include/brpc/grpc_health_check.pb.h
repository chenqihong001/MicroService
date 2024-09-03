// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: brpc/grpc_health_check.proto
// Protobuf C++ Version: 4.25.1

#ifndef GOOGLE_PROTOBUF_INCLUDED_brpc_2fgrpc_5fhealth_5fcheck_2eproto_2epb_2eh
#define GOOGLE_PROTOBUF_INCLUDED_brpc_2fgrpc_5fhealth_5fcheck_2eproto_2epb_2eh

#include <limits>
#include <string>
#include <type_traits>
#include <utility>

#include "google/protobuf/port_def.inc"
#if PROTOBUF_VERSION < 4025000
#error "This file was generated by a newer version of protoc which is"
#error "incompatible with your Protocol Buffer headers. Please update"
#error "your headers."
#endif  // PROTOBUF_VERSION

#if 4025001 < PROTOBUF_MIN_PROTOC_VERSION
#error "This file was generated by an older version of protoc which is"
#error "incompatible with your Protocol Buffer headers. Please"
#error "regenerate this file with a newer version of protoc."
#endif  // PROTOBUF_MIN_PROTOC_VERSION
#include "google/protobuf/port_undef.inc"
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/arena.h"
#include "google/protobuf/arenastring.h"
#include "google/protobuf/generated_message_tctable_decl.h"
#include "google/protobuf/generated_message_util.h"
#include "google/protobuf/metadata_lite.h"
#include "google/protobuf/generated_message_reflection.h"
#include "google/protobuf/message.h"
#include "google/protobuf/repeated_field.h"  // IWYU pragma: export
#include "google/protobuf/extension_set.h"  // IWYU pragma: export
#include "google/protobuf/generated_enum_reflection.h"
#include "google/protobuf/service.h"
#include "google/protobuf/unknown_field_set.h"
// @@protoc_insertion_point(includes)

// Must be included last.
#include "google/protobuf/port_def.inc"

#define PROTOBUF_INTERNAL_EXPORT_brpc_2fgrpc_5fhealth_5fcheck_2eproto

namespace google {
namespace protobuf {
namespace internal {
class AnyMetadata;
}  // namespace internal
}  // namespace protobuf
}  // namespace google

// Internal implementation detail -- do not use these members.
struct TableStruct_brpc_2fgrpc_5fhealth_5fcheck_2eproto {
  static const ::uint32_t offsets[];
};
extern const ::google::protobuf::internal::DescriptorTable
    descriptor_table_brpc_2fgrpc_5fhealth_5fcheck_2eproto;
namespace grpc {
namespace health {
namespace v1 {
class HealthCheckRequest;
struct HealthCheckRequestDefaultTypeInternal;
extern HealthCheckRequestDefaultTypeInternal _HealthCheckRequest_default_instance_;
class HealthCheckResponse;
struct HealthCheckResponseDefaultTypeInternal;
extern HealthCheckResponseDefaultTypeInternal _HealthCheckResponse_default_instance_;
}  // namespace v1
}  // namespace health
}  // namespace grpc
namespace google {
namespace protobuf {
}  // namespace protobuf
}  // namespace google

namespace grpc {
namespace health {
namespace v1 {
enum HealthCheckResponse_ServingStatus : int {
  HealthCheckResponse_ServingStatus_UNKNOWN = 0,
  HealthCheckResponse_ServingStatus_SERVING = 1,
  HealthCheckResponse_ServingStatus_NOT_SERVING = 2,
  HealthCheckResponse_ServingStatus_SERVICE_UNKNOWN = 3,
};

bool HealthCheckResponse_ServingStatus_IsValid(int value);
extern const uint32_t HealthCheckResponse_ServingStatus_internal_data_[];
constexpr HealthCheckResponse_ServingStatus HealthCheckResponse_ServingStatus_ServingStatus_MIN = static_cast<HealthCheckResponse_ServingStatus>(0);
constexpr HealthCheckResponse_ServingStatus HealthCheckResponse_ServingStatus_ServingStatus_MAX = static_cast<HealthCheckResponse_ServingStatus>(3);
constexpr int HealthCheckResponse_ServingStatus_ServingStatus_ARRAYSIZE = 3 + 1;
const ::google::protobuf::EnumDescriptor*
HealthCheckResponse_ServingStatus_descriptor();
template <typename T>
const std::string& HealthCheckResponse_ServingStatus_Name(T value) {
  static_assert(std::is_same<T, HealthCheckResponse_ServingStatus>::value ||
                    std::is_integral<T>::value,
                "Incorrect type passed to ServingStatus_Name().");
  return HealthCheckResponse_ServingStatus_Name(static_cast<HealthCheckResponse_ServingStatus>(value));
}
template <>
inline const std::string& HealthCheckResponse_ServingStatus_Name(HealthCheckResponse_ServingStatus value) {
  return ::google::protobuf::internal::NameOfDenseEnum<HealthCheckResponse_ServingStatus_descriptor,
                                                 0, 3>(
      static_cast<int>(value));
}
inline bool HealthCheckResponse_ServingStatus_Parse(absl::string_view name, HealthCheckResponse_ServingStatus* value) {
  return ::google::protobuf::internal::ParseNamedEnum<HealthCheckResponse_ServingStatus>(
      HealthCheckResponse_ServingStatus_descriptor(), name, value);
}

// ===================================================================


// -------------------------------------------------------------------

class HealthCheckResponse final :
    public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:grpc.health.v1.HealthCheckResponse) */ {
 public:
  inline HealthCheckResponse() : HealthCheckResponse(nullptr) {}
  ~HealthCheckResponse() override;
  template<typename = void>
  explicit PROTOBUF_CONSTEXPR HealthCheckResponse(::google::protobuf::internal::ConstantInitialized);

  inline HealthCheckResponse(const HealthCheckResponse& from)
      : HealthCheckResponse(nullptr, from) {}
  HealthCheckResponse(HealthCheckResponse&& from) noexcept
    : HealthCheckResponse() {
    *this = ::std::move(from);
  }

  inline HealthCheckResponse& operator=(const HealthCheckResponse& from) {
    CopyFrom(from);
    return *this;
  }
  inline HealthCheckResponse& operator=(HealthCheckResponse&& from) noexcept {
    if (this == &from) return *this;
    if (GetArena() == from.GetArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return _internal_metadata_.unknown_fields<::google::protobuf::UnknownFieldSet>(::google::protobuf::UnknownFieldSet::default_instance);
  }
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields()
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return _internal_metadata_.mutable_unknown_fields<::google::protobuf::UnknownFieldSet>();
  }

  static const ::google::protobuf::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::google::protobuf::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::google::protobuf::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const HealthCheckResponse& default_instance() {
    return *internal_default_instance();
  }
  static inline const HealthCheckResponse* internal_default_instance() {
    return reinterpret_cast<const HealthCheckResponse*>(
               &_HealthCheckResponse_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  friend void swap(HealthCheckResponse& a, HealthCheckResponse& b) {
    a.Swap(&b);
  }
  inline void Swap(HealthCheckResponse* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetArena() != nullptr &&
        GetArena() == other->GetArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetArena() == other->GetArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::google::protobuf::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(HealthCheckResponse* other) {
    if (other == this) return;
    ABSL_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  HealthCheckResponse* New(::google::protobuf::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<HealthCheckResponse>(arena);
  }
  using ::google::protobuf::Message::CopyFrom;
  void CopyFrom(const HealthCheckResponse& from);
  using ::google::protobuf::Message::MergeFrom;
  void MergeFrom( const HealthCheckResponse& from) {
    HealthCheckResponse::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::google::protobuf::Message& to_msg, const ::google::protobuf::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  ::size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::google::protobuf::internal::ParseContext* ctx) final;
  ::uint8_t* _InternalSerialize(
      ::uint8_t* target, ::google::protobuf::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const { return _impl_._cached_size_.Get(); }

  private:
  ::google::protobuf::internal::CachedSize* AccessCachedSize() const final;
  void SharedCtor(::google::protobuf::Arena* arena);
  void SharedDtor();
  void InternalSwap(HealthCheckResponse* other);

  private:
  friend class ::google::protobuf::internal::AnyMetadata;
  static ::absl::string_view FullMessageName() {
    return "grpc.health.v1.HealthCheckResponse";
  }
  protected:
  explicit HealthCheckResponse(::google::protobuf::Arena* arena);
  HealthCheckResponse(::google::protobuf::Arena* arena, const HealthCheckResponse& from);
  public:

  static const ClassData _class_data_;
  const ::google::protobuf::Message::ClassData*GetClassData() const final;

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  using ServingStatus = HealthCheckResponse_ServingStatus;
  static constexpr ServingStatus UNKNOWN = HealthCheckResponse_ServingStatus_UNKNOWN;
  static constexpr ServingStatus SERVING = HealthCheckResponse_ServingStatus_SERVING;
  static constexpr ServingStatus NOT_SERVING = HealthCheckResponse_ServingStatus_NOT_SERVING;
  static constexpr ServingStatus SERVICE_UNKNOWN = HealthCheckResponse_ServingStatus_SERVICE_UNKNOWN;
  static inline bool ServingStatus_IsValid(int value) {
    return HealthCheckResponse_ServingStatus_IsValid(value);
  }
  static constexpr ServingStatus ServingStatus_MIN = HealthCheckResponse_ServingStatus_ServingStatus_MIN;
  static constexpr ServingStatus ServingStatus_MAX = HealthCheckResponse_ServingStatus_ServingStatus_MAX;
  static constexpr int ServingStatus_ARRAYSIZE = HealthCheckResponse_ServingStatus_ServingStatus_ARRAYSIZE;
  static inline const ::google::protobuf::EnumDescriptor* ServingStatus_descriptor() {
    return HealthCheckResponse_ServingStatus_descriptor();
  }
  template <typename T>
  static inline const std::string& ServingStatus_Name(T value) {
    return HealthCheckResponse_ServingStatus_Name(value);
  }
  static inline bool ServingStatus_Parse(absl::string_view name, ServingStatus* value) {
    return HealthCheckResponse_ServingStatus_Parse(name, value);
  }

  // accessors -------------------------------------------------------

  enum : int {
    kStatusFieldNumber = 1,
  };
  // optional .grpc.health.v1.HealthCheckResponse.ServingStatus status = 1;
  bool has_status() const;
  void clear_status() ;
  ::grpc::health::v1::HealthCheckResponse_ServingStatus status() const;
  void set_status(::grpc::health::v1::HealthCheckResponse_ServingStatus value);

  private:
  ::grpc::health::v1::HealthCheckResponse_ServingStatus _internal_status() const;
  void _internal_set_status(::grpc::health::v1::HealthCheckResponse_ServingStatus value);

  public:
  // @@protoc_insertion_point(class_scope:grpc.health.v1.HealthCheckResponse)
 private:
  class _Internal;

  friend class ::google::protobuf::internal::TcParser;
  static const ::google::protobuf::internal::TcParseTable<
      0, 1, 1,
      0, 2>
      _table_;
  friend class ::google::protobuf::MessageLite;
  friend class ::google::protobuf::Arena;
  template <typename T>
  friend class ::google::protobuf::Arena::InternalHelper;
  using InternalArenaConstructable_ = void;
  using DestructorSkippable_ = void;
  struct Impl_ {

        inline explicit constexpr Impl_(
            ::google::protobuf::internal::ConstantInitialized) noexcept;
        inline explicit Impl_(::google::protobuf::internal::InternalVisibility visibility,
                              ::google::protobuf::Arena* arena);
        inline explicit Impl_(::google::protobuf::internal::InternalVisibility visibility,
                              ::google::protobuf::Arena* arena, const Impl_& from);
    ::google::protobuf::internal::HasBits<1> _has_bits_;
    mutable ::google::protobuf::internal::CachedSize _cached_size_;
    int status_;
    PROTOBUF_TSAN_DECLARE_MEMBER
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_brpc_2fgrpc_5fhealth_5fcheck_2eproto;
};// -------------------------------------------------------------------

class HealthCheckRequest final :
    public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:grpc.health.v1.HealthCheckRequest) */ {
 public:
  inline HealthCheckRequest() : HealthCheckRequest(nullptr) {}
  ~HealthCheckRequest() override;
  template<typename = void>
  explicit PROTOBUF_CONSTEXPR HealthCheckRequest(::google::protobuf::internal::ConstantInitialized);

  inline HealthCheckRequest(const HealthCheckRequest& from)
      : HealthCheckRequest(nullptr, from) {}
  HealthCheckRequest(HealthCheckRequest&& from) noexcept
    : HealthCheckRequest() {
    *this = ::std::move(from);
  }

  inline HealthCheckRequest& operator=(const HealthCheckRequest& from) {
    CopyFrom(from);
    return *this;
  }
  inline HealthCheckRequest& operator=(HealthCheckRequest&& from) noexcept {
    if (this == &from) return *this;
    if (GetArena() == from.GetArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return _internal_metadata_.unknown_fields<::google::protobuf::UnknownFieldSet>(::google::protobuf::UnknownFieldSet::default_instance);
  }
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields()
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return _internal_metadata_.mutable_unknown_fields<::google::protobuf::UnknownFieldSet>();
  }

  static const ::google::protobuf::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::google::protobuf::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::google::protobuf::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const HealthCheckRequest& default_instance() {
    return *internal_default_instance();
  }
  static inline const HealthCheckRequest* internal_default_instance() {
    return reinterpret_cast<const HealthCheckRequest*>(
               &_HealthCheckRequest_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(HealthCheckRequest& a, HealthCheckRequest& b) {
    a.Swap(&b);
  }
  inline void Swap(HealthCheckRequest* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetArena() != nullptr &&
        GetArena() == other->GetArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetArena() == other->GetArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::google::protobuf::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(HealthCheckRequest* other) {
    if (other == this) return;
    ABSL_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  HealthCheckRequest* New(::google::protobuf::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<HealthCheckRequest>(arena);
  }
  using ::google::protobuf::Message::CopyFrom;
  void CopyFrom(const HealthCheckRequest& from);
  using ::google::protobuf::Message::MergeFrom;
  void MergeFrom( const HealthCheckRequest& from) {
    HealthCheckRequest::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::google::protobuf::Message& to_msg, const ::google::protobuf::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  ::size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::google::protobuf::internal::ParseContext* ctx) final;
  ::uint8_t* _InternalSerialize(
      ::uint8_t* target, ::google::protobuf::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const { return _impl_._cached_size_.Get(); }

  private:
  ::google::protobuf::internal::CachedSize* AccessCachedSize() const final;
  void SharedCtor(::google::protobuf::Arena* arena);
  void SharedDtor();
  void InternalSwap(HealthCheckRequest* other);

  private:
  friend class ::google::protobuf::internal::AnyMetadata;
  static ::absl::string_view FullMessageName() {
    return "grpc.health.v1.HealthCheckRequest";
  }
  protected:
  explicit HealthCheckRequest(::google::protobuf::Arena* arena);
  HealthCheckRequest(::google::protobuf::Arena* arena, const HealthCheckRequest& from);
  public:

  static const ClassData _class_data_;
  const ::google::protobuf::Message::ClassData*GetClassData() const final;

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kServiceFieldNumber = 1,
  };
  // optional string service = 1;
  bool has_service() const;
  void clear_service() ;
  const std::string& service() const;
  template <typename Arg_ = const std::string&, typename... Args_>
  void set_service(Arg_&& arg, Args_... args);
  std::string* mutable_service();
  PROTOBUF_NODISCARD std::string* release_service();
  void set_allocated_service(std::string* value);

  private:
  const std::string& _internal_service() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_service(
      const std::string& value);
  std::string* _internal_mutable_service();

  public:
  // @@protoc_insertion_point(class_scope:grpc.health.v1.HealthCheckRequest)
 private:
  class _Internal;

  friend class ::google::protobuf::internal::TcParser;
  static const ::google::protobuf::internal::TcParseTable<
      0, 1, 0,
      49, 2>
      _table_;
  friend class ::google::protobuf::MessageLite;
  friend class ::google::protobuf::Arena;
  template <typename T>
  friend class ::google::protobuf::Arena::InternalHelper;
  using InternalArenaConstructable_ = void;
  using DestructorSkippable_ = void;
  struct Impl_ {

        inline explicit constexpr Impl_(
            ::google::protobuf::internal::ConstantInitialized) noexcept;
        inline explicit Impl_(::google::protobuf::internal::InternalVisibility visibility,
                              ::google::protobuf::Arena* arena);
        inline explicit Impl_(::google::protobuf::internal::InternalVisibility visibility,
                              ::google::protobuf::Arena* arena, const Impl_& from);
    ::google::protobuf::internal::HasBits<1> _has_bits_;
    mutable ::google::protobuf::internal::CachedSize _cached_size_;
    ::google::protobuf::internal::ArenaStringPtr service_;
    PROTOBUF_TSAN_DECLARE_MEMBER
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_brpc_2fgrpc_5fhealth_5fcheck_2eproto;
};

// ===================================================================


// -------------------------------------------------------------------

class Health_Stub;
class Health : public ::google::protobuf::Service {
 protected:
  Health() = default;

 public:
  using Stub = Health_Stub;

  Health(const Health&) = delete;
  Health& operator=(const Health&) = delete;
  virtual ~Health() = default;

  static const ::google::protobuf::ServiceDescriptor* descriptor();

  virtual void Check(::google::protobuf::RpcController* controller,
                        const ::grpc::health::v1::HealthCheckRequest* request,
                        ::grpc::health::v1::HealthCheckResponse* response,
                        ::google::protobuf::Closure* done);
  virtual void Watch(::google::protobuf::RpcController* controller,
                        const ::grpc::health::v1::HealthCheckRequest* request,
                        ::grpc::health::v1::HealthCheckResponse* response,
                        ::google::protobuf::Closure* done);

  // implements Service ----------------------------------------------
  const ::google::protobuf::ServiceDescriptor* GetDescriptor() override;

  void CallMethod(const ::google::protobuf::MethodDescriptor* method,
                  ::google::protobuf::RpcController* controller,
                  const ::google::protobuf::Message* request,
                  ::google::protobuf::Message* response,
                  ::google::protobuf::Closure* done) override;

  const ::google::protobuf::Message& GetRequestPrototype(
      const ::google::protobuf::MethodDescriptor* method) const override;

  const ::google::protobuf::Message& GetResponsePrototype(
      const ::google::protobuf::MethodDescriptor* method) const override;
};

class Health_Stub final : public Health {
 public:
  Health_Stub(::google::protobuf::RpcChannel* channel);
  Health_Stub(::google::protobuf::RpcChannel* channel,
                   ::google::protobuf::Service::ChannelOwnership ownership);

  Health_Stub(const Health_Stub&) = delete;
  Health_Stub& operator=(const Health_Stub&) = delete;

  ~Health_Stub() override;

  inline ::google::protobuf::RpcChannel* channel() { return channel_; }

  // implements Health ------------------------------------------
  void Check(::google::protobuf::RpcController* controller,
                        const ::grpc::health::v1::HealthCheckRequest* request,
                        ::grpc::health::v1::HealthCheckResponse* response,
                        ::google::protobuf::Closure* done) override;
  void Watch(::google::protobuf::RpcController* controller,
                        const ::grpc::health::v1::HealthCheckRequest* request,
                        ::grpc::health::v1::HealthCheckResponse* response,
                        ::google::protobuf::Closure* done) override;

 private:
  ::google::protobuf::RpcChannel* channel_;
  bool owns_channel_;
};
// ===================================================================



// ===================================================================


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// -------------------------------------------------------------------

// HealthCheckRequest

// optional string service = 1;
inline bool HealthCheckRequest::has_service() const {
  bool value = (_impl_._has_bits_[0] & 0x00000001u) != 0;
  return value;
}
inline void HealthCheckRequest::clear_service() {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_.service_.ClearToEmpty();
  _impl_._has_bits_[0] &= ~0x00000001u;
}
inline const std::string& HealthCheckRequest::service() const
    ABSL_ATTRIBUTE_LIFETIME_BOUND {
  // @@protoc_insertion_point(field_get:grpc.health.v1.HealthCheckRequest.service)
  return _internal_service();
}
template <typename Arg_, typename... Args_>
inline PROTOBUF_ALWAYS_INLINE void HealthCheckRequest::set_service(Arg_&& arg,
                                                     Args_... args) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000001u;
  _impl_.service_.Set(static_cast<Arg_&&>(arg), args..., GetArena());
  // @@protoc_insertion_point(field_set:grpc.health.v1.HealthCheckRequest.service)
}
inline std::string* HealthCheckRequest::mutable_service() ABSL_ATTRIBUTE_LIFETIME_BOUND {
  std::string* _s = _internal_mutable_service();
  // @@protoc_insertion_point(field_mutable:grpc.health.v1.HealthCheckRequest.service)
  return _s;
}
inline const std::string& HealthCheckRequest::_internal_service() const {
  PROTOBUF_TSAN_READ(&_impl_._tsan_detect_race);
  return _impl_.service_.Get();
}
inline void HealthCheckRequest::_internal_set_service(const std::string& value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000001u;
  _impl_.service_.Set(value, GetArena());
}
inline std::string* HealthCheckRequest::_internal_mutable_service() {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000001u;
  return _impl_.service_.Mutable( GetArena());
}
inline std::string* HealthCheckRequest::release_service() {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  // @@protoc_insertion_point(field_release:grpc.health.v1.HealthCheckRequest.service)
  if ((_impl_._has_bits_[0] & 0x00000001u) == 0) {
    return nullptr;
  }
  _impl_._has_bits_[0] &= ~0x00000001u;
  auto* released = _impl_.service_.Release();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.service_.Set("", GetArena());
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  return released;
}
inline void HealthCheckRequest::set_allocated_service(std::string* value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  if (value != nullptr) {
    _impl_._has_bits_[0] |= 0x00000001u;
  } else {
    _impl_._has_bits_[0] &= ~0x00000001u;
  }
  _impl_.service_.SetAllocated(value, GetArena());
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
        if (_impl_.service_.IsDefault()) {
          _impl_.service_.Set("", GetArena());
        }
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:grpc.health.v1.HealthCheckRequest.service)
}

// -------------------------------------------------------------------

// HealthCheckResponse

// optional .grpc.health.v1.HealthCheckResponse.ServingStatus status = 1;
inline bool HealthCheckResponse::has_status() const {
  bool value = (_impl_._has_bits_[0] & 0x00000001u) != 0;
  return value;
}
inline void HealthCheckResponse::clear_status() {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_.status_ = 0;
  _impl_._has_bits_[0] &= ~0x00000001u;
}
inline ::grpc::health::v1::HealthCheckResponse_ServingStatus HealthCheckResponse::status() const {
  // @@protoc_insertion_point(field_get:grpc.health.v1.HealthCheckResponse.status)
  return _internal_status();
}
inline void HealthCheckResponse::set_status(::grpc::health::v1::HealthCheckResponse_ServingStatus value) {
  _internal_set_status(value);
  // @@protoc_insertion_point(field_set:grpc.health.v1.HealthCheckResponse.status)
}
inline ::grpc::health::v1::HealthCheckResponse_ServingStatus HealthCheckResponse::_internal_status() const {
  PROTOBUF_TSAN_READ(&_impl_._tsan_detect_race);
  return static_cast<::grpc::health::v1::HealthCheckResponse_ServingStatus>(_impl_.status_);
}
inline void HealthCheckResponse::_internal_set_status(::grpc::health::v1::HealthCheckResponse_ServingStatus value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  assert(::grpc::health::v1::HealthCheckResponse_ServingStatus_IsValid(value));
  _impl_._has_bits_[0] |= 0x00000001u;
  _impl_.status_ = value;
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)
}  // namespace v1
}  // namespace health
}  // namespace grpc


namespace google {
namespace protobuf {

template <>
struct is_proto_enum<::grpc::health::v1::HealthCheckResponse_ServingStatus> : std::true_type {};
template <>
inline const EnumDescriptor* GetEnumDescriptor<::grpc::health::v1::HealthCheckResponse_ServingStatus>() {
  return ::grpc::health::v1::HealthCheckResponse_ServingStatus_descriptor();
}

}  // namespace protobuf
}  // namespace google

// @@protoc_insertion_point(global_scope)

#include "google/protobuf/port_undef.inc"

#endif  // GOOGLE_PROTOBUF_INCLUDED_brpc_2fgrpc_5fhealth_5fcheck_2eproto_2epb_2eh
