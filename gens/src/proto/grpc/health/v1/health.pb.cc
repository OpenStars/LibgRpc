// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: src/proto/grpc/health/v1/health.proto

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "src/proto/grpc/health/v1/health.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/port.h>
#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)

namespace grpc {
namespace health {
namespace v1 {
class HealthCheckRequestDefaultTypeInternal : public ::google::protobuf::internal::ExplicitlyConstructed<HealthCheckRequest> {
} _HealthCheckRequest_default_instance_;
class HealthCheckResponseDefaultTypeInternal : public ::google::protobuf::internal::ExplicitlyConstructed<HealthCheckResponse> {
} _HealthCheckResponse_default_instance_;

namespace protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto {


namespace {

::google::protobuf::Metadata file_level_metadata[2];
const ::google::protobuf::EnumDescriptor* file_level_enum_descriptors[1];

}  // namespace

PROTOBUF_CONSTEXPR_VAR ::google::protobuf::internal::ParseTableField
    const TableStruct::entries[] = {
  {0, 0, 0, ::google::protobuf::internal::kInvalidMask, 0, 0},
};

PROTOBUF_CONSTEXPR_VAR ::google::protobuf::internal::AuxillaryParseTableField
    const TableStruct::aux[] = {
  ::google::protobuf::internal::AuxillaryParseTableField(),
};
PROTOBUF_CONSTEXPR_VAR ::google::protobuf::internal::ParseTable const
    TableStruct::schema[] = {
  { NULL, NULL, 0, -1, -1, false },
  { NULL, NULL, 0, -1, -1, false },
};

const ::google::protobuf::uint32 TableStruct::offsets[] = {
  ~0u,  // no _has_bits_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(HealthCheckRequest, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(HealthCheckRequest, service_),
  ~0u,  // no _has_bits_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(HealthCheckResponse, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(HealthCheckResponse, status_),
};

static const ::google::protobuf::internal::MigrationSchema schemas[] = {
  { 0, -1, sizeof(HealthCheckRequest)},
  { 6, -1, sizeof(HealthCheckResponse)},
};

static ::google::protobuf::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::google::protobuf::Message*>(&_HealthCheckRequest_default_instance_),
  reinterpret_cast<const ::google::protobuf::Message*>(&_HealthCheckResponse_default_instance_),
};

namespace {

void protobuf_AssignDescriptors() {
  AddDescriptors();
  ::google::protobuf::MessageFactory* factory = NULL;
  AssignDescriptors(
      "src/proto/grpc/health/v1/health.proto", schemas, file_default_instances, TableStruct::offsets, factory,
      file_level_metadata, file_level_enum_descriptors, NULL);
}

void protobuf_AssignDescriptorsOnce() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &protobuf_AssignDescriptors);
}

void protobuf_RegisterTypes(const ::std::string&) GOOGLE_ATTRIBUTE_COLD;
void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::internal::RegisterAllTypes(file_level_metadata, 2);
}

}  // namespace

void TableStruct::Shutdown() {
  _HealthCheckRequest_default_instance_.Shutdown();
  delete file_level_metadata[0].reflection;
  _HealthCheckResponse_default_instance_.Shutdown();
  delete file_level_metadata[1].reflection;
}

void TableStruct::InitDefaultsImpl() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::google::protobuf::internal::InitProtobufDefaults();
  _HealthCheckRequest_default_instance_.DefaultConstruct();
  _HealthCheckResponse_default_instance_.DefaultConstruct();
}

void InitDefaults() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &TableStruct::InitDefaultsImpl);
}
void AddDescriptorsImpl() {
  InitDefaults();
  static const char descriptor[] = {
      "\n%src/proto/grpc/health/v1/health.proto\022"
      "\016grpc.health.v1\"%\n\022HealthCheckRequest\022\017\n"
      "\007service\030\001 \001(\t\"\224\001\n\023HealthCheckResponse\022A"
      "\n\006status\030\001 \001(\01621.grpc.health.v1.HealthCh"
      "eckResponse.ServingStatus\":\n\rServingStat"
      "us\022\013\n\007UNKNOWN\020\000\022\013\n\007SERVING\020\001\022\017\n\013NOT_SERV"
      "ING\020\0022Z\n\006Health\022P\n\005Check\022\".grpc.health.v"
      "1.HealthCheckRequest\032#.grpc.health.v1.He"
      "althCheckResponseB\021\252\002\016Grpc.Health.V1b\006pr"
      "oto3"
  };
  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
      descriptor, 364);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "src/proto/grpc/health/v1/health.proto", &protobuf_RegisterTypes);
  ::google::protobuf::internal::OnShutdown(&TableStruct::Shutdown);
}

void AddDescriptors() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &AddDescriptorsImpl);
}
// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer {
  StaticDescriptorInitializer() {
    AddDescriptors();
  }
} static_descriptor_initializer;

}  // namespace protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto

const ::google::protobuf::EnumDescriptor* HealthCheckResponse_ServingStatus_descriptor() {
  protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::file_level_enum_descriptors[0];
}
bool HealthCheckResponse_ServingStatus_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
    case 2:
      return true;
    default:
      return false;
  }
}

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const HealthCheckResponse_ServingStatus HealthCheckResponse::UNKNOWN;
const HealthCheckResponse_ServingStatus HealthCheckResponse::SERVING;
const HealthCheckResponse_ServingStatus HealthCheckResponse::NOT_SERVING;
const HealthCheckResponse_ServingStatus HealthCheckResponse::ServingStatus_MIN;
const HealthCheckResponse_ServingStatus HealthCheckResponse::ServingStatus_MAX;
const int HealthCheckResponse::ServingStatus_ARRAYSIZE;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

// ===================================================================

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int HealthCheckRequest::kServiceFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

HealthCheckRequest::HealthCheckRequest()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  if (GOOGLE_PREDICT_TRUE(this != internal_default_instance())) {
    protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::InitDefaults();
  }
  SharedCtor();
  // @@protoc_insertion_point(constructor:grpc.health.v1.HealthCheckRequest)
}
HealthCheckRequest::HealthCheckRequest(const HealthCheckRequest& from)
  : ::google::protobuf::Message(),
      _internal_metadata_(NULL),
      _cached_size_(0) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  service_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  if (from.service().size() > 0) {
    service_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.service_);
  }
  // @@protoc_insertion_point(copy_constructor:grpc.health.v1.HealthCheckRequest)
}

void HealthCheckRequest::SharedCtor() {
  service_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  _cached_size_ = 0;
}

HealthCheckRequest::~HealthCheckRequest() {
  // @@protoc_insertion_point(destructor:grpc.health.v1.HealthCheckRequest)
  SharedDtor();
}

void HealthCheckRequest::SharedDtor() {
  service_.DestroyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}

void HealthCheckRequest::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* HealthCheckRequest::descriptor() {
  protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::file_level_metadata[kIndexInFileMessages].descriptor;
}

const HealthCheckRequest& HealthCheckRequest::default_instance() {
  protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::InitDefaults();
  return *internal_default_instance();
}

HealthCheckRequest* HealthCheckRequest::New(::google::protobuf::Arena* arena) const {
  HealthCheckRequest* n = new HealthCheckRequest;
  if (arena != NULL) {
    arena->Own(n);
  }
  return n;
}

void HealthCheckRequest::Clear() {
// @@protoc_insertion_point(message_clear_start:grpc.health.v1.HealthCheckRequest)
  service_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}

bool HealthCheckRequest::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:grpc.health.v1.HealthCheckRequest)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // string service = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(10u)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_service()));
          DO_(::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
            this->service().data(), this->service().length(),
            ::google::protobuf::internal::WireFormatLite::PARSE,
            "grpc.health.v1.HealthCheckRequest.service"));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0 ||
            ::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormatLite::SkipField(input, tag));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:grpc.health.v1.HealthCheckRequest)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:grpc.health.v1.HealthCheckRequest)
  return false;
#undef DO_
}

void HealthCheckRequest::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:grpc.health.v1.HealthCheckRequest)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // string service = 1;
  if (this->service().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
      this->service().data(), this->service().length(),
      ::google::protobuf::internal::WireFormatLite::SERIALIZE,
      "grpc.health.v1.HealthCheckRequest.service");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      1, this->service(), output);
  }

  // @@protoc_insertion_point(serialize_end:grpc.health.v1.HealthCheckRequest)
}

::google::protobuf::uint8* HealthCheckRequest::InternalSerializeWithCachedSizesToArray(
    bool deterministic, ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:grpc.health.v1.HealthCheckRequest)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // string service = 1;
  if (this->service().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
      this->service().data(), this->service().length(),
      ::google::protobuf::internal::WireFormatLite::SERIALIZE,
      "grpc.health.v1.HealthCheckRequest.service");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        1, this->service(), target);
  }

  // @@protoc_insertion_point(serialize_to_array_end:grpc.health.v1.HealthCheckRequest)
  return target;
}

size_t HealthCheckRequest::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:grpc.health.v1.HealthCheckRequest)
  size_t total_size = 0;

  // string service = 1;
  if (this->service().size() > 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::StringSize(
        this->service());
  }

  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = cached_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void HealthCheckRequest::MergeFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:grpc.health.v1.HealthCheckRequest)
  GOOGLE_DCHECK_NE(&from, this);
  const HealthCheckRequest* source =
      ::google::protobuf::internal::DynamicCastToGenerated<const HealthCheckRequest>(
          &from);
  if (source == NULL) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:grpc.health.v1.HealthCheckRequest)
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:grpc.health.v1.HealthCheckRequest)
    MergeFrom(*source);
  }
}

void HealthCheckRequest::MergeFrom(const HealthCheckRequest& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:grpc.health.v1.HealthCheckRequest)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.service().size() > 0) {

    service_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.service_);
  }
}

void HealthCheckRequest::CopyFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:grpc.health.v1.HealthCheckRequest)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void HealthCheckRequest::CopyFrom(const HealthCheckRequest& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:grpc.health.v1.HealthCheckRequest)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool HealthCheckRequest::IsInitialized() const {
  return true;
}

void HealthCheckRequest::Swap(HealthCheckRequest* other) {
  if (other == this) return;
  InternalSwap(other);
}
void HealthCheckRequest::InternalSwap(HealthCheckRequest* other) {
  service_.Swap(&other->service_);
  std::swap(_cached_size_, other->_cached_size_);
}

::google::protobuf::Metadata HealthCheckRequest::GetMetadata() const {
  protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::file_level_metadata[kIndexInFileMessages];
}

#if PROTOBUF_INLINE_NOT_IN_HEADERS
// HealthCheckRequest

// string service = 1;
void HealthCheckRequest::clear_service() {
  service_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
const ::std::string& HealthCheckRequest::service() const {
  // @@protoc_insertion_point(field_get:grpc.health.v1.HealthCheckRequest.service)
  return service_.GetNoArena();
}
void HealthCheckRequest::set_service(const ::std::string& value) {
  
  service_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:grpc.health.v1.HealthCheckRequest.service)
}
#if LANG_CXX11
void HealthCheckRequest::set_service(::std::string&& value) {
  
  service_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:grpc.health.v1.HealthCheckRequest.service)
}
#endif
void HealthCheckRequest::set_service(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  service_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:grpc.health.v1.HealthCheckRequest.service)
}
void HealthCheckRequest::set_service(const char* value, size_t size) {
  
  service_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:grpc.health.v1.HealthCheckRequest.service)
}
::std::string* HealthCheckRequest::mutable_service() {
  
  // @@protoc_insertion_point(field_mutable:grpc.health.v1.HealthCheckRequest.service)
  return service_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
::std::string* HealthCheckRequest::release_service() {
  // @@protoc_insertion_point(field_release:grpc.health.v1.HealthCheckRequest.service)
  
  return service_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
void HealthCheckRequest::set_allocated_service(::std::string* service) {
  if (service != NULL) {
    
  } else {
    
  }
  service_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), service);
  // @@protoc_insertion_point(field_set_allocated:grpc.health.v1.HealthCheckRequest.service)
}

#endif  // PROTOBUF_INLINE_NOT_IN_HEADERS

// ===================================================================

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int HealthCheckResponse::kStatusFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

HealthCheckResponse::HealthCheckResponse()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  if (GOOGLE_PREDICT_TRUE(this != internal_default_instance())) {
    protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::InitDefaults();
  }
  SharedCtor();
  // @@protoc_insertion_point(constructor:grpc.health.v1.HealthCheckResponse)
}
HealthCheckResponse::HealthCheckResponse(const HealthCheckResponse& from)
  : ::google::protobuf::Message(),
      _internal_metadata_(NULL),
      _cached_size_(0) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  status_ = from.status_;
  // @@protoc_insertion_point(copy_constructor:grpc.health.v1.HealthCheckResponse)
}

void HealthCheckResponse::SharedCtor() {
  status_ = 0;
  _cached_size_ = 0;
}

HealthCheckResponse::~HealthCheckResponse() {
  // @@protoc_insertion_point(destructor:grpc.health.v1.HealthCheckResponse)
  SharedDtor();
}

void HealthCheckResponse::SharedDtor() {
}

void HealthCheckResponse::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* HealthCheckResponse::descriptor() {
  protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::file_level_metadata[kIndexInFileMessages].descriptor;
}

const HealthCheckResponse& HealthCheckResponse::default_instance() {
  protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::InitDefaults();
  return *internal_default_instance();
}

HealthCheckResponse* HealthCheckResponse::New(::google::protobuf::Arena* arena) const {
  HealthCheckResponse* n = new HealthCheckResponse;
  if (arena != NULL) {
    arena->Own(n);
  }
  return n;
}

void HealthCheckResponse::Clear() {
// @@protoc_insertion_point(message_clear_start:grpc.health.v1.HealthCheckResponse)
  status_ = 0;
}

bool HealthCheckResponse::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:grpc.health.v1.HealthCheckResponse)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // .grpc.health.v1.HealthCheckResponse.ServingStatus status = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(8u)) {
          int value;
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   int, ::google::protobuf::internal::WireFormatLite::TYPE_ENUM>(
                 input, &value)));
          set_status(static_cast< ::grpc::health::v1::HealthCheckResponse_ServingStatus >(value));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0 ||
            ::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormatLite::SkipField(input, tag));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:grpc.health.v1.HealthCheckResponse)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:grpc.health.v1.HealthCheckResponse)
  return false;
#undef DO_
}

void HealthCheckResponse::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:grpc.health.v1.HealthCheckResponse)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .grpc.health.v1.HealthCheckResponse.ServingStatus status = 1;
  if (this->status() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteEnum(
      1, this->status(), output);
  }

  // @@protoc_insertion_point(serialize_end:grpc.health.v1.HealthCheckResponse)
}

::google::protobuf::uint8* HealthCheckResponse::InternalSerializeWithCachedSizesToArray(
    bool deterministic, ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:grpc.health.v1.HealthCheckResponse)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .grpc.health.v1.HealthCheckResponse.ServingStatus status = 1;
  if (this->status() != 0) {
    target = ::google::protobuf::internal::WireFormatLite::WriteEnumToArray(
      1, this->status(), target);
  }

  // @@protoc_insertion_point(serialize_to_array_end:grpc.health.v1.HealthCheckResponse)
  return target;
}

size_t HealthCheckResponse::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:grpc.health.v1.HealthCheckResponse)
  size_t total_size = 0;

  // .grpc.health.v1.HealthCheckResponse.ServingStatus status = 1;
  if (this->status() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::EnumSize(this->status());
  }

  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = cached_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void HealthCheckResponse::MergeFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:grpc.health.v1.HealthCheckResponse)
  GOOGLE_DCHECK_NE(&from, this);
  const HealthCheckResponse* source =
      ::google::protobuf::internal::DynamicCastToGenerated<const HealthCheckResponse>(
          &from);
  if (source == NULL) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:grpc.health.v1.HealthCheckResponse)
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:grpc.health.v1.HealthCheckResponse)
    MergeFrom(*source);
  }
}

void HealthCheckResponse::MergeFrom(const HealthCheckResponse& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:grpc.health.v1.HealthCheckResponse)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.status() != 0) {
    set_status(from.status());
  }
}

void HealthCheckResponse::CopyFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:grpc.health.v1.HealthCheckResponse)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void HealthCheckResponse::CopyFrom(const HealthCheckResponse& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:grpc.health.v1.HealthCheckResponse)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool HealthCheckResponse::IsInitialized() const {
  return true;
}

void HealthCheckResponse::Swap(HealthCheckResponse* other) {
  if (other == this) return;
  InternalSwap(other);
}
void HealthCheckResponse::InternalSwap(HealthCheckResponse* other) {
  std::swap(status_, other->status_);
  std::swap(_cached_size_, other->_cached_size_);
}

::google::protobuf::Metadata HealthCheckResponse::GetMetadata() const {
  protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_src_2fproto_2fgrpc_2fhealth_2fv1_2fhealth_2eproto::file_level_metadata[kIndexInFileMessages];
}

#if PROTOBUF_INLINE_NOT_IN_HEADERS
// HealthCheckResponse

// .grpc.health.v1.HealthCheckResponse.ServingStatus status = 1;
void HealthCheckResponse::clear_status() {
  status_ = 0;
}
::grpc::health::v1::HealthCheckResponse_ServingStatus HealthCheckResponse::status() const {
  // @@protoc_insertion_point(field_get:grpc.health.v1.HealthCheckResponse.status)
  return static_cast< ::grpc::health::v1::HealthCheckResponse_ServingStatus >(status_);
}
void HealthCheckResponse::set_status(::grpc::health::v1::HealthCheckResponse_ServingStatus value) {
  
  status_ = value;
  // @@protoc_insertion_point(field_set:grpc.health.v1.HealthCheckResponse.status)
}

#endif  // PROTOBUF_INLINE_NOT_IN_HEADERS

// @@protoc_insertion_point(namespace_scope)

}  // namespace v1
}  // namespace health
}  // namespace grpc

// @@protoc_insertion_point(global_scope)