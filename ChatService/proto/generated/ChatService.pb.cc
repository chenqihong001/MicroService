// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: ChatService.proto

#include "ChatService.pb.h"

#include <algorithm>
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/extension_set.h"
#include "google/protobuf/wire_format_lite.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/generated_message_reflection.h"
#include "google/protobuf/reflection_ops.h"
#include "google/protobuf/wire_format.h"
#include "google/protobuf/generated_message_tctable_impl.h"
// @@protoc_insertion_point(includes)

// Must be included last.
#include "google/protobuf/port_def.inc"
PROTOBUF_PRAGMA_INIT_SEG
namespace _pb = ::google::protobuf;
namespace _pbi = ::google::protobuf::internal;
namespace _fl = ::google::protobuf::internal::field_layout;
namespace chat {

inline constexpr User::Impl_::Impl_(
    ::_pbi::ConstantInitialized) noexcept
      : username_(
            &::google::protobuf::internal::fixed_address_empty_string,
            ::_pbi::ConstantInitialized()),
        _cached_size_{0} {}

template <typename>
PROTOBUF_CONSTEXPR User::User(::_pbi::ConstantInitialized)
    : _impl_(::_pbi::ConstantInitialized()) {}
struct UserDefaultTypeInternal {
  PROTOBUF_CONSTEXPR UserDefaultTypeInternal() : _instance(::_pbi::ConstantInitialized{}) {}
  ~UserDefaultTypeInternal() {}
  union {
    User _instance;
  };
};

PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT
    PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 UserDefaultTypeInternal _User_default_instance_;

inline constexpr ChatReply::Impl_::Impl_(
    ::_pbi::ConstantInitialized) noexcept
      : status_(
            &::google::protobuf::internal::fixed_address_empty_string,
            ::_pbi::ConstantInitialized()),
        _cached_size_{0} {}

template <typename>
PROTOBUF_CONSTEXPR ChatReply::ChatReply(::_pbi::ConstantInitialized)
    : _impl_(::_pbi::ConstantInitialized()) {}
struct ChatReplyDefaultTypeInternal {
  PROTOBUF_CONSTEXPR ChatReplyDefaultTypeInternal() : _instance(::_pbi::ConstantInitialized{}) {}
  ~ChatReplyDefaultTypeInternal() {}
  union {
    ChatReply _instance;
  };
};

PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT
    PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 ChatReplyDefaultTypeInternal _ChatReply_default_instance_;

inline constexpr ChatMessage::Impl_::Impl_(
    ::_pbi::ConstantInitialized) noexcept
      : username_(
            &::google::protobuf::internal::fixed_address_empty_string,
            ::_pbi::ConstantInitialized()),
        message_(
            &::google::protobuf::internal::fixed_address_empty_string,
            ::_pbi::ConstantInitialized()),
        _cached_size_{0} {}

template <typename>
PROTOBUF_CONSTEXPR ChatMessage::ChatMessage(::_pbi::ConstantInitialized)
    : _impl_(::_pbi::ConstantInitialized()) {}
struct ChatMessageDefaultTypeInternal {
  PROTOBUF_CONSTEXPR ChatMessageDefaultTypeInternal() : _instance(::_pbi::ConstantInitialized{}) {}
  ~ChatMessageDefaultTypeInternal() {}
  union {
    ChatMessage _instance;
  };
};

PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT
    PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 ChatMessageDefaultTypeInternal _ChatMessage_default_instance_;
}  // namespace chat
static ::_pb::Metadata file_level_metadata_ChatService_2eproto[3];
static constexpr const ::_pb::EnumDescriptor**
    file_level_enum_descriptors_ChatService_2eproto = nullptr;
static constexpr const ::_pb::ServiceDescriptor**
    file_level_service_descriptors_ChatService_2eproto = nullptr;
const ::uint32_t TableStruct_ChatService_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(
    protodesc_cold) = {
    ~0u,  // no _has_bits_
    PROTOBUF_FIELD_OFFSET(::chat::User, _internal_metadata_),
    ~0u,  // no _extensions_
    ~0u,  // no _oneof_case_
    ~0u,  // no _weak_field_map_
    ~0u,  // no _inlined_string_donated_
    ~0u,  // no _split_
    ~0u,  // no sizeof(Split)
    PROTOBUF_FIELD_OFFSET(::chat::User, _impl_.username_),
    ~0u,  // no _has_bits_
    PROTOBUF_FIELD_OFFSET(::chat::ChatMessage, _internal_metadata_),
    ~0u,  // no _extensions_
    ~0u,  // no _oneof_case_
    ~0u,  // no _weak_field_map_
    ~0u,  // no _inlined_string_donated_
    ~0u,  // no _split_
    ~0u,  // no sizeof(Split)
    PROTOBUF_FIELD_OFFSET(::chat::ChatMessage, _impl_.username_),
    PROTOBUF_FIELD_OFFSET(::chat::ChatMessage, _impl_.message_),
    ~0u,  // no _has_bits_
    PROTOBUF_FIELD_OFFSET(::chat::ChatReply, _internal_metadata_),
    ~0u,  // no _extensions_
    ~0u,  // no _oneof_case_
    ~0u,  // no _weak_field_map_
    ~0u,  // no _inlined_string_donated_
    ~0u,  // no _split_
    ~0u,  // no sizeof(Split)
    PROTOBUF_FIELD_OFFSET(::chat::ChatReply, _impl_.status_),
};

static const ::_pbi::MigrationSchema
    schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
        {0, -1, -1, sizeof(::chat::User)},
        {9, -1, -1, sizeof(::chat::ChatMessage)},
        {19, -1, -1, sizeof(::chat::ChatReply)},
};

static const ::_pb::Message* const file_default_instances[] = {
    &::chat::_User_default_instance_._instance,
    &::chat::_ChatMessage_default_instance_._instance,
    &::chat::_ChatReply_default_instance_._instance,
};
const char descriptor_table_protodef_ChatService_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
    "\n\021ChatService.proto\022\004chat\"\030\n\004User\022\020\n\010use"
    "rname\030\001 \001(\t\"0\n\013ChatMessage\022\020\n\010username\030\001"
    " \001(\t\022\017\n\007message\030\002 \001(\t\"\033\n\tChatReply\022\016\n\006st"
    "atus\030\001 \001(\t2t\n\013ChatService\0221\n\013SendMessage"
    "\022\021.chat.ChatMessage\032\017.chat.ChatReply\0222\n\017"
    "ReceiveMessages\022\n.chat.User\032\021.chat.ChatM"
    "essage0\001b\006proto3"
};
static ::absl::once_flag descriptor_table_ChatService_2eproto_once;
const ::_pbi::DescriptorTable descriptor_table_ChatService_2eproto = {
    false,
    false,
    256,
    descriptor_table_protodef_ChatService_2eproto,
    "ChatService.proto",
    &descriptor_table_ChatService_2eproto_once,
    nullptr,
    0,
    3,
    schemas,
    file_default_instances,
    TableStruct_ChatService_2eproto::offsets,
    file_level_metadata_ChatService_2eproto,
    file_level_enum_descriptors_ChatService_2eproto,
    file_level_service_descriptors_ChatService_2eproto,
};

// This function exists to be marked as weak.
// It can significantly speed up compilation by breaking up LLVM's SCC
// in the .pb.cc translation units. Large translation units see a
// reduction of more than 35% of walltime for optimized builds. Without
// the weak attribute all the messages in the file, including all the
// vtables and everything they use become part of the same SCC through
// a cycle like:
// GetMetadata -> descriptor table -> default instances ->
//   vtables -> GetMetadata
// By adding a weak function here we break the connection from the
// individual vtables back into the descriptor table.
PROTOBUF_ATTRIBUTE_WEAK const ::_pbi::DescriptorTable* descriptor_table_ChatService_2eproto_getter() {
  return &descriptor_table_ChatService_2eproto;
}
// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY2
static ::_pbi::AddDescriptorsRunner dynamic_init_dummy_ChatService_2eproto(&descriptor_table_ChatService_2eproto);
namespace chat {
// ===================================================================

class User::_Internal {
 public:
};

User::User(::google::protobuf::Arena* arena)
    : ::google::protobuf::Message(arena) {
  SharedCtor(arena);
  // @@protoc_insertion_point(arena_constructor:chat.User)
}
inline PROTOBUF_NDEBUG_INLINE User::Impl_::Impl_(
    ::google::protobuf::internal::InternalVisibility visibility, ::google::protobuf::Arena* arena,
    const Impl_& from)
      : username_(arena, from.username_),
        _cached_size_{0} {}

User::User(
    ::google::protobuf::Arena* arena,
    const User& from)
    : ::google::protobuf::Message(arena) {
  User* const _this = this;
  (void)_this;
  _internal_metadata_.MergeFrom<::google::protobuf::UnknownFieldSet>(
      from._internal_metadata_);
  new (&_impl_) Impl_(internal_visibility(), arena, from._impl_);

  // @@protoc_insertion_point(copy_constructor:chat.User)
}
inline PROTOBUF_NDEBUG_INLINE User::Impl_::Impl_(
    ::google::protobuf::internal::InternalVisibility visibility,
    ::google::protobuf::Arena* arena)
      : username_(arena),
        _cached_size_{0} {}

inline void User::SharedCtor(::_pb::Arena* arena) {
  new (&_impl_) Impl_(internal_visibility(), arena);
}
User::~User() {
  // @@protoc_insertion_point(destructor:chat.User)
  _internal_metadata_.Delete<::google::protobuf::UnknownFieldSet>();
  SharedDtor();
}
inline void User::SharedDtor() {
  ABSL_DCHECK(GetArena() == nullptr);
  _impl_.username_.Destroy();
  _impl_.~Impl_();
}

PROTOBUF_NOINLINE void User::Clear() {
// @@protoc_insertion_point(message_clear_start:chat.User)
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.username_.ClearToEmpty();
  _internal_metadata_.Clear<::google::protobuf::UnknownFieldSet>();
}

const char* User::_InternalParse(
    const char* ptr, ::_pbi::ParseContext* ctx) {
  ptr = ::_pbi::TcParser::ParseLoop(this, ptr, ctx, &_table_.header);
  return ptr;
}


PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1
const ::_pbi::TcParseTable<0, 1, 0, 26, 2> User::_table_ = {
  {
    0,  // no _has_bits_
    0, // no _extensions_
    1, 0,  // max_field_number, fast_idx_mask
    offsetof(decltype(_table_), field_lookup_table),
    4294967294,  // skipmap
    offsetof(decltype(_table_), field_entries),
    1,  // num_field_entries
    0,  // num_aux_entries
    offsetof(decltype(_table_), field_names),  // no aux_entries
    &_User_default_instance_._instance,
    ::_pbi::TcParser::GenericFallback,  // fallback
  }, {{
    // string username = 1;
    {::_pbi::TcParser::FastUS1,
     {10, 63, 0, PROTOBUF_FIELD_OFFSET(User, _impl_.username_)}},
  }}, {{
    65535, 65535
  }}, {{
    // string username = 1;
    {PROTOBUF_FIELD_OFFSET(User, _impl_.username_), 0, 0,
    (0 | ::_fl::kFcSingular | ::_fl::kUtf8String | ::_fl::kRepAString)},
  }},
  // no aux_entries
  {{
    "\11\10\0\0\0\0\0\0"
    "chat.User"
    "username"
  }},
};

::uint8_t* User::_InternalSerialize(
    ::uint8_t* target,
    ::google::protobuf::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:chat.User)
  ::uint32_t cached_has_bits = 0;
  (void)cached_has_bits;

  // string username = 1;
  if (!this->_internal_username().empty()) {
    const std::string& _s = this->_internal_username();
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
        _s.data(), static_cast<int>(_s.length()), ::google::protobuf::internal::WireFormatLite::SERIALIZE, "chat.User.username");
    target = stream->WriteStringMaybeAliased(1, _s, target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target =
        ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
            _internal_metadata_.unknown_fields<::google::protobuf::UnknownFieldSet>(::google::protobuf::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:chat.User)
  return target;
}

::size_t User::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:chat.User)
  ::size_t total_size = 0;

  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string username = 1;
  if (!this->_internal_username().empty()) {
    total_size += 1 + ::google::protobuf::internal::WireFormatLite::StringSize(
                                    this->_internal_username());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::google::protobuf::Message::ClassData User::_class_data_ = {
    User::MergeImpl,
    nullptr,  // OnDemandRegisterArenaDtor
};
const ::google::protobuf::Message::ClassData* User::GetClassData() const {
  return &_class_data_;
}

void User::MergeImpl(::google::protobuf::Message& to_msg, const ::google::protobuf::Message& from_msg) {
  auto* const _this = static_cast<User*>(&to_msg);
  auto& from = static_cast<const User&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:chat.User)
  ABSL_DCHECK_NE(&from, _this);
  ::uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_username().empty()) {
    _this->_internal_set_username(from._internal_username());
  }
  _this->_internal_metadata_.MergeFrom<::google::protobuf::UnknownFieldSet>(from._internal_metadata_);
}

void User::CopyFrom(const User& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:chat.User)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

PROTOBUF_NOINLINE bool User::IsInitialized() const {
  return true;
}

::_pbi::CachedSize* User::AccessCachedSize() const {
  return &_impl_._cached_size_;
}
void User::InternalSwap(User* PROTOBUF_RESTRICT other) {
  using std::swap;
  auto* arena = GetArena();
  ABSL_DCHECK_EQ(arena, other->GetArena());
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::_pbi::ArenaStringPtr::InternalSwap(&_impl_.username_, &other->_impl_.username_, arena);
}

::google::protobuf::Metadata User::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_ChatService_2eproto_getter, &descriptor_table_ChatService_2eproto_once,
      file_level_metadata_ChatService_2eproto[0]);
}
// ===================================================================

class ChatMessage::_Internal {
 public:
};

ChatMessage::ChatMessage(::google::protobuf::Arena* arena)
    : ::google::protobuf::Message(arena) {
  SharedCtor(arena);
  // @@protoc_insertion_point(arena_constructor:chat.ChatMessage)
}
inline PROTOBUF_NDEBUG_INLINE ChatMessage::Impl_::Impl_(
    ::google::protobuf::internal::InternalVisibility visibility, ::google::protobuf::Arena* arena,
    const Impl_& from)
      : username_(arena, from.username_),
        message_(arena, from.message_),
        _cached_size_{0} {}

ChatMessage::ChatMessage(
    ::google::protobuf::Arena* arena,
    const ChatMessage& from)
    : ::google::protobuf::Message(arena) {
  ChatMessage* const _this = this;
  (void)_this;
  _internal_metadata_.MergeFrom<::google::protobuf::UnknownFieldSet>(
      from._internal_metadata_);
  new (&_impl_) Impl_(internal_visibility(), arena, from._impl_);

  // @@protoc_insertion_point(copy_constructor:chat.ChatMessage)
}
inline PROTOBUF_NDEBUG_INLINE ChatMessage::Impl_::Impl_(
    ::google::protobuf::internal::InternalVisibility visibility,
    ::google::protobuf::Arena* arena)
      : username_(arena),
        message_(arena),
        _cached_size_{0} {}

inline void ChatMessage::SharedCtor(::_pb::Arena* arena) {
  new (&_impl_) Impl_(internal_visibility(), arena);
}
ChatMessage::~ChatMessage() {
  // @@protoc_insertion_point(destructor:chat.ChatMessage)
  _internal_metadata_.Delete<::google::protobuf::UnknownFieldSet>();
  SharedDtor();
}
inline void ChatMessage::SharedDtor() {
  ABSL_DCHECK(GetArena() == nullptr);
  _impl_.username_.Destroy();
  _impl_.message_.Destroy();
  _impl_.~Impl_();
}

PROTOBUF_NOINLINE void ChatMessage::Clear() {
// @@protoc_insertion_point(message_clear_start:chat.ChatMessage)
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.username_.ClearToEmpty();
  _impl_.message_.ClearToEmpty();
  _internal_metadata_.Clear<::google::protobuf::UnknownFieldSet>();
}

const char* ChatMessage::_InternalParse(
    const char* ptr, ::_pbi::ParseContext* ctx) {
  ptr = ::_pbi::TcParser::ParseLoop(this, ptr, ctx, &_table_.header);
  return ptr;
}


PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1
const ::_pbi::TcParseTable<1, 2, 0, 40, 2> ChatMessage::_table_ = {
  {
    0,  // no _has_bits_
    0, // no _extensions_
    2, 8,  // max_field_number, fast_idx_mask
    offsetof(decltype(_table_), field_lookup_table),
    4294967292,  // skipmap
    offsetof(decltype(_table_), field_entries),
    2,  // num_field_entries
    0,  // num_aux_entries
    offsetof(decltype(_table_), field_names),  // no aux_entries
    &_ChatMessage_default_instance_._instance,
    ::_pbi::TcParser::GenericFallback,  // fallback
  }, {{
    // string message = 2;
    {::_pbi::TcParser::FastUS1,
     {18, 63, 0, PROTOBUF_FIELD_OFFSET(ChatMessage, _impl_.message_)}},
    // string username = 1;
    {::_pbi::TcParser::FastUS1,
     {10, 63, 0, PROTOBUF_FIELD_OFFSET(ChatMessage, _impl_.username_)}},
  }}, {{
    65535, 65535
  }}, {{
    // string username = 1;
    {PROTOBUF_FIELD_OFFSET(ChatMessage, _impl_.username_), 0, 0,
    (0 | ::_fl::kFcSingular | ::_fl::kUtf8String | ::_fl::kRepAString)},
    // string message = 2;
    {PROTOBUF_FIELD_OFFSET(ChatMessage, _impl_.message_), 0, 0,
    (0 | ::_fl::kFcSingular | ::_fl::kUtf8String | ::_fl::kRepAString)},
  }},
  // no aux_entries
  {{
    "\20\10\7\0\0\0\0\0"
    "chat.ChatMessage"
    "username"
    "message"
  }},
};

::uint8_t* ChatMessage::_InternalSerialize(
    ::uint8_t* target,
    ::google::protobuf::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:chat.ChatMessage)
  ::uint32_t cached_has_bits = 0;
  (void)cached_has_bits;

  // string username = 1;
  if (!this->_internal_username().empty()) {
    const std::string& _s = this->_internal_username();
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
        _s.data(), static_cast<int>(_s.length()), ::google::protobuf::internal::WireFormatLite::SERIALIZE, "chat.ChatMessage.username");
    target = stream->WriteStringMaybeAliased(1, _s, target);
  }

  // string message = 2;
  if (!this->_internal_message().empty()) {
    const std::string& _s = this->_internal_message();
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
        _s.data(), static_cast<int>(_s.length()), ::google::protobuf::internal::WireFormatLite::SERIALIZE, "chat.ChatMessage.message");
    target = stream->WriteStringMaybeAliased(2, _s, target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target =
        ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
            _internal_metadata_.unknown_fields<::google::protobuf::UnknownFieldSet>(::google::protobuf::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:chat.ChatMessage)
  return target;
}

::size_t ChatMessage::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:chat.ChatMessage)
  ::size_t total_size = 0;

  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string username = 1;
  if (!this->_internal_username().empty()) {
    total_size += 1 + ::google::protobuf::internal::WireFormatLite::StringSize(
                                    this->_internal_username());
  }

  // string message = 2;
  if (!this->_internal_message().empty()) {
    total_size += 1 + ::google::protobuf::internal::WireFormatLite::StringSize(
                                    this->_internal_message());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::google::protobuf::Message::ClassData ChatMessage::_class_data_ = {
    ChatMessage::MergeImpl,
    nullptr,  // OnDemandRegisterArenaDtor
};
const ::google::protobuf::Message::ClassData* ChatMessage::GetClassData() const {
  return &_class_data_;
}

void ChatMessage::MergeImpl(::google::protobuf::Message& to_msg, const ::google::protobuf::Message& from_msg) {
  auto* const _this = static_cast<ChatMessage*>(&to_msg);
  auto& from = static_cast<const ChatMessage&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:chat.ChatMessage)
  ABSL_DCHECK_NE(&from, _this);
  ::uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_username().empty()) {
    _this->_internal_set_username(from._internal_username());
  }
  if (!from._internal_message().empty()) {
    _this->_internal_set_message(from._internal_message());
  }
  _this->_internal_metadata_.MergeFrom<::google::protobuf::UnknownFieldSet>(from._internal_metadata_);
}

void ChatMessage::CopyFrom(const ChatMessage& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:chat.ChatMessage)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

PROTOBUF_NOINLINE bool ChatMessage::IsInitialized() const {
  return true;
}

::_pbi::CachedSize* ChatMessage::AccessCachedSize() const {
  return &_impl_._cached_size_;
}
void ChatMessage::InternalSwap(ChatMessage* PROTOBUF_RESTRICT other) {
  using std::swap;
  auto* arena = GetArena();
  ABSL_DCHECK_EQ(arena, other->GetArena());
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::_pbi::ArenaStringPtr::InternalSwap(&_impl_.username_, &other->_impl_.username_, arena);
  ::_pbi::ArenaStringPtr::InternalSwap(&_impl_.message_, &other->_impl_.message_, arena);
}

::google::protobuf::Metadata ChatMessage::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_ChatService_2eproto_getter, &descriptor_table_ChatService_2eproto_once,
      file_level_metadata_ChatService_2eproto[1]);
}
// ===================================================================

class ChatReply::_Internal {
 public:
};

ChatReply::ChatReply(::google::protobuf::Arena* arena)
    : ::google::protobuf::Message(arena) {
  SharedCtor(arena);
  // @@protoc_insertion_point(arena_constructor:chat.ChatReply)
}
inline PROTOBUF_NDEBUG_INLINE ChatReply::Impl_::Impl_(
    ::google::protobuf::internal::InternalVisibility visibility, ::google::protobuf::Arena* arena,
    const Impl_& from)
      : status_(arena, from.status_),
        _cached_size_{0} {}

ChatReply::ChatReply(
    ::google::protobuf::Arena* arena,
    const ChatReply& from)
    : ::google::protobuf::Message(arena) {
  ChatReply* const _this = this;
  (void)_this;
  _internal_metadata_.MergeFrom<::google::protobuf::UnknownFieldSet>(
      from._internal_metadata_);
  new (&_impl_) Impl_(internal_visibility(), arena, from._impl_);

  // @@protoc_insertion_point(copy_constructor:chat.ChatReply)
}
inline PROTOBUF_NDEBUG_INLINE ChatReply::Impl_::Impl_(
    ::google::protobuf::internal::InternalVisibility visibility,
    ::google::protobuf::Arena* arena)
      : status_(arena),
        _cached_size_{0} {}

inline void ChatReply::SharedCtor(::_pb::Arena* arena) {
  new (&_impl_) Impl_(internal_visibility(), arena);
}
ChatReply::~ChatReply() {
  // @@protoc_insertion_point(destructor:chat.ChatReply)
  _internal_metadata_.Delete<::google::protobuf::UnknownFieldSet>();
  SharedDtor();
}
inline void ChatReply::SharedDtor() {
  ABSL_DCHECK(GetArena() == nullptr);
  _impl_.status_.Destroy();
  _impl_.~Impl_();
}

PROTOBUF_NOINLINE void ChatReply::Clear() {
// @@protoc_insertion_point(message_clear_start:chat.ChatReply)
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.status_.ClearToEmpty();
  _internal_metadata_.Clear<::google::protobuf::UnknownFieldSet>();
}

const char* ChatReply::_InternalParse(
    const char* ptr, ::_pbi::ParseContext* ctx) {
  ptr = ::_pbi::TcParser::ParseLoop(this, ptr, ctx, &_table_.header);
  return ptr;
}


PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1
const ::_pbi::TcParseTable<0, 1, 0, 29, 2> ChatReply::_table_ = {
  {
    0,  // no _has_bits_
    0, // no _extensions_
    1, 0,  // max_field_number, fast_idx_mask
    offsetof(decltype(_table_), field_lookup_table),
    4294967294,  // skipmap
    offsetof(decltype(_table_), field_entries),
    1,  // num_field_entries
    0,  // num_aux_entries
    offsetof(decltype(_table_), field_names),  // no aux_entries
    &_ChatReply_default_instance_._instance,
    ::_pbi::TcParser::GenericFallback,  // fallback
  }, {{
    // string status = 1;
    {::_pbi::TcParser::FastUS1,
     {10, 63, 0, PROTOBUF_FIELD_OFFSET(ChatReply, _impl_.status_)}},
  }}, {{
    65535, 65535
  }}, {{
    // string status = 1;
    {PROTOBUF_FIELD_OFFSET(ChatReply, _impl_.status_), 0, 0,
    (0 | ::_fl::kFcSingular | ::_fl::kUtf8String | ::_fl::kRepAString)},
  }},
  // no aux_entries
  {{
    "\16\6\0\0\0\0\0\0"
    "chat.ChatReply"
    "status"
  }},
};

::uint8_t* ChatReply::_InternalSerialize(
    ::uint8_t* target,
    ::google::protobuf::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:chat.ChatReply)
  ::uint32_t cached_has_bits = 0;
  (void)cached_has_bits;

  // string status = 1;
  if (!this->_internal_status().empty()) {
    const std::string& _s = this->_internal_status();
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
        _s.data(), static_cast<int>(_s.length()), ::google::protobuf::internal::WireFormatLite::SERIALIZE, "chat.ChatReply.status");
    target = stream->WriteStringMaybeAliased(1, _s, target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target =
        ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
            _internal_metadata_.unknown_fields<::google::protobuf::UnknownFieldSet>(::google::protobuf::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:chat.ChatReply)
  return target;
}

::size_t ChatReply::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:chat.ChatReply)
  ::size_t total_size = 0;

  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string status = 1;
  if (!this->_internal_status().empty()) {
    total_size += 1 + ::google::protobuf::internal::WireFormatLite::StringSize(
                                    this->_internal_status());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::google::protobuf::Message::ClassData ChatReply::_class_data_ = {
    ChatReply::MergeImpl,
    nullptr,  // OnDemandRegisterArenaDtor
};
const ::google::protobuf::Message::ClassData* ChatReply::GetClassData() const {
  return &_class_data_;
}

void ChatReply::MergeImpl(::google::protobuf::Message& to_msg, const ::google::protobuf::Message& from_msg) {
  auto* const _this = static_cast<ChatReply*>(&to_msg);
  auto& from = static_cast<const ChatReply&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:chat.ChatReply)
  ABSL_DCHECK_NE(&from, _this);
  ::uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_status().empty()) {
    _this->_internal_set_status(from._internal_status());
  }
  _this->_internal_metadata_.MergeFrom<::google::protobuf::UnknownFieldSet>(from._internal_metadata_);
}

void ChatReply::CopyFrom(const ChatReply& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:chat.ChatReply)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

PROTOBUF_NOINLINE bool ChatReply::IsInitialized() const {
  return true;
}

::_pbi::CachedSize* ChatReply::AccessCachedSize() const {
  return &_impl_._cached_size_;
}
void ChatReply::InternalSwap(ChatReply* PROTOBUF_RESTRICT other) {
  using std::swap;
  auto* arena = GetArena();
  ABSL_DCHECK_EQ(arena, other->GetArena());
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::_pbi::ArenaStringPtr::InternalSwap(&_impl_.status_, &other->_impl_.status_, arena);
}

::google::protobuf::Metadata ChatReply::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_ChatService_2eproto_getter, &descriptor_table_ChatService_2eproto_once,
      file_level_metadata_ChatService_2eproto[2]);
}
// @@protoc_insertion_point(namespace_scope)
}  // namespace chat
namespace google {
namespace protobuf {
}  // namespace protobuf
}  // namespace google
// @@protoc_insertion_point(global_scope)
#include "google/protobuf/port_undef.inc"