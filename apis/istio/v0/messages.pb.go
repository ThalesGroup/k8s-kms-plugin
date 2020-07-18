//
//Copyright 2018 The Kubernetes Authors.
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.21.0
// 	protoc        v3.10.0
// source: apis/istio/v0/messages.proto

package istio

import (
	proto "github.com/golang/protobuf/proto"
	_ "github.com/golang/protobuf/ptypes/timestamp"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger/options"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type KeyKind int32

const (
	KeyKind_UNKNOWN KeyKind = 0
	KeyKind_AES     KeyKind = 1
	KeyKind_RSA     KeyKind = 2
	KeyKind_ECC     KeyKind = 3
)

// Enum value maps for KeyKind.
var (
	KeyKind_name = map[int32]string{
		0: "UNKNOWN",
		1: "AES",
		2: "RSA",
		3: "ECC",
	}
	KeyKind_value = map[string]int32{
		"UNKNOWN": 0,
		"AES":     1,
		"RSA":     2,
		"ECC":     3,
	}
)

func (x KeyKind) Enum() *KeyKind {
	p := new(KeyKind)
	*p = x
	return p
}

func (x KeyKind) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (KeyKind) Descriptor() protoreflect.EnumDescriptor {
	return file_apis_istio_v0_messages_proto_enumTypes[0].Descriptor()
}

func (KeyKind) Type() protoreflect.EnumType {
	return &file_apis_istio_v0_messages_proto_enumTypes[0]
}

func (x KeyKind) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use KeyKind.Descriptor instead.
func (KeyKind) EnumDescriptor() ([]byte, []int) {
	return file_apis_istio_v0_messages_proto_rawDescGZIP(), []int{0}
}

type VersionRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Version of the KMS plugin API.
	Version string `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *VersionRequest) Reset() {
	*x = VersionRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_istio_v0_messages_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VersionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VersionRequest) ProtoMessage() {}

func (x *VersionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_apis_istio_v0_messages_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VersionRequest.ProtoReflect.Descriptor instead.
func (*VersionRequest) Descriptor() ([]byte, []int) {
	return file_apis_istio_v0_messages_proto_rawDescGZIP(), []int{0}
}

func (x *VersionRequest) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

type VersionResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Version of the KMS plugin API.
	Version string `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	// Name of the KMS provider.
	RuntimeName string `protobuf:"bytes,2,opt,name=runtime_name,json=runtimeName,proto3" json:"runtime_name,omitempty"`
	// Version of the KMS provider. The string must be semver-compatible.
	RuntimeVersion string `protobuf:"bytes,3,opt,name=runtime_version,json=runtimeVersion,proto3" json:"runtime_version,omitempty"`
}

func (x *VersionResponse) Reset() {
	*x = VersionResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_istio_v0_messages_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VersionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VersionResponse) ProtoMessage() {}

func (x *VersionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_apis_istio_v0_messages_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VersionResponse.ProtoReflect.Descriptor instead.
func (*VersionResponse) Descriptor() ([]byte, []int) {
	return file_apis_istio_v0_messages_proto_rawDescGZIP(), []int{1}
}

func (x *VersionResponse) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *VersionResponse) GetRuntimeName() string {
	if x != nil {
		return x.RuntimeName
	}
	return ""
}

func (x *VersionResponse) GetRuntimeVersion() string {
	if x != nil {
		return x.RuntimeVersion
	}
	return ""
}

type GenerateDEKRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// key size in bits
	Size int64 `protobuf:"varint,1,opt,name=size,proto3" json:"size,omitempty"`
	// What kind of key is it... only Assymmetric kinds will be supported
	Kind KeyKind `protobuf:"varint,2,opt,name=kind,proto3,enum=thalescpl.io.ekms.istio.v0.KeyKind" json:"kind,omitempty"`
}

func (x *GenerateDEKRequest) Reset() {
	*x = GenerateDEKRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_istio_v0_messages_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateDEKRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateDEKRequest) ProtoMessage() {}

func (x *GenerateDEKRequest) ProtoReflect() protoreflect.Message {
	mi := &file_apis_istio_v0_messages_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateDEKRequest.ProtoReflect.Descriptor instead.
func (*GenerateDEKRequest) Descriptor() ([]byte, []int) {
	return file_apis_istio_v0_messages_proto_rawDescGZIP(), []int{2}
}

func (x *GenerateDEKRequest) GetSize() int64 {
	if x != nil {
		return x.Size
	}
	return 0
}

func (x *GenerateDEKRequest) GetKind() KeyKind {
	if x != nil {
		return x.Kind
	}
	return KeyKind_UNKNOWN
}

type GenerateDEKResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Encrypted key blob
	EncryptedKeyBlob []byte `protobuf:"bytes,1,opt,name=encrypted_key_blob,json=encryptedKeyBlob,proto3" json:"encrypted_key_blob,omitempty"`
}

func (x *GenerateDEKResponse) Reset() {
	*x = GenerateDEKResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_istio_v0_messages_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateDEKResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateDEKResponse) ProtoMessage() {}

func (x *GenerateDEKResponse) ProtoReflect() protoreflect.Message {
	mi := &file_apis_istio_v0_messages_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateDEKResponse.ProtoReflect.Descriptor instead.
func (*GenerateDEKResponse) Descriptor() ([]byte, []int) {
	return file_apis_istio_v0_messages_proto_rawDescGZIP(), []int{3}
}

func (x *GenerateDEKResponse) GetEncryptedKeyBlob() []byte {
	if x != nil {
		return x.EncryptedKeyBlob
	}
	return nil
}

type GenerateSEKRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// key size in bits
	Size int64 `protobuf:"varint,1,opt,name=size,proto3" json:"size,omitempty"`
	// What kind of key is it... only Assymmetric kinds will be supported
	Kind KeyKind `protobuf:"varint,2,opt,name=kind,proto3,enum=thalescpl.io.ekms.istio.v0.KeyKind" json:"kind,omitempty"`
	// Encrypted blob of DEK
	EncryptedKeyBlob []byte `protobuf:"bytes,3,opt,name=encrypted_key_blob,json=encryptedKeyBlob,proto3" json:"encrypted_key_blob,omitempty"`
}

func (x *GenerateSEKRequest) Reset() {
	*x = GenerateSEKRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_istio_v0_messages_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateSEKRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateSEKRequest) ProtoMessage() {}

func (x *GenerateSEKRequest) ProtoReflect() protoreflect.Message {
	mi := &file_apis_istio_v0_messages_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateSEKRequest.ProtoReflect.Descriptor instead.
func (*GenerateSEKRequest) Descriptor() ([]byte, []int) {
	return file_apis_istio_v0_messages_proto_rawDescGZIP(), []int{4}
}

func (x *GenerateSEKRequest) GetSize() int64 {
	if x != nil {
		return x.Size
	}
	return 0
}

func (x *GenerateSEKRequest) GetKind() KeyKind {
	if x != nil {
		return x.Kind
	}
	return KeyKind_UNKNOWN
}

func (x *GenerateSEKRequest) GetEncryptedKeyBlob() []byte {
	if x != nil {
		return x.EncryptedKeyBlob
	}
	return nil
}

type GenerateSEKResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Encrypted blob of SEK encrypted by DEK
	EncryptedKeyBlob []byte `protobuf:"bytes,1,opt,name=encrypted_key_blob,json=encryptedKeyBlob,proto3" json:"encrypted_key_blob,omitempty"`
}

func (x *GenerateSEKResponse) Reset() {
	*x = GenerateSEKResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_istio_v0_messages_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateSEKResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateSEKResponse) ProtoMessage() {}

func (x *GenerateSEKResponse) ProtoReflect() protoreflect.Message {
	mi := &file_apis_istio_v0_messages_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateSEKResponse.ProtoReflect.Descriptor instead.
func (*GenerateSEKResponse) Descriptor() ([]byte, []int) {
	return file_apis_istio_v0_messages_proto_rawDescGZIP(), []int{5}
}

func (x *GenerateSEKResponse) GetEncryptedKeyBlob() []byte {
	if x != nil {
		return x.EncryptedKeyBlob
	}
	return nil
}

type LoadDEKRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Encrypted blob of DEK
	EncryptedKeyBlob []byte `protobuf:"bytes,1,opt,name=encrypted_key_blob,json=encryptedKeyBlob,proto3" json:"encrypted_key_blob,omitempty"`
	// What kind of key is it... only Assymmetric kinds will be supported
	Kind KeyKind `protobuf:"varint,2,opt,name=kind,proto3,enum=thalescpl.io.ekms.istio.v0.KeyKind" json:"kind,omitempty"`
}

func (x *LoadDEKRequest) Reset() {
	*x = LoadDEKRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_istio_v0_messages_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LoadDEKRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoadDEKRequest) ProtoMessage() {}

func (x *LoadDEKRequest) ProtoReflect() protoreflect.Message {
	mi := &file_apis_istio_v0_messages_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoadDEKRequest.ProtoReflect.Descriptor instead.
func (*LoadDEKRequest) Descriptor() ([]byte, []int) {
	return file_apis_istio_v0_messages_proto_rawDescGZIP(), []int{6}
}

func (x *LoadDEKRequest) GetEncryptedKeyBlob() []byte {
	if x != nil {
		return x.EncryptedKeyBlob
	}
	return nil
}

func (x *LoadDEKRequest) GetKind() KeyKind {
	if x != nil {
		return x.Kind
	}
	return KeyKind_UNKNOWN
}

type LoadDEKResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Clear DEK
	ClearKey []byte `protobuf:"bytes,1,opt,name=clear_key,json=clearKey,proto3" json:"clear_key,omitempty"`
}

func (x *LoadDEKResponse) Reset() {
	*x = LoadDEKResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apis_istio_v0_messages_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LoadDEKResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoadDEKResponse) ProtoMessage() {}

func (x *LoadDEKResponse) ProtoReflect() protoreflect.Message {
	mi := &file_apis_istio_v0_messages_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoadDEKResponse.ProtoReflect.Descriptor instead.
func (*LoadDEKResponse) Descriptor() ([]byte, []int) {
	return file_apis_istio_v0_messages_proto_rawDescGZIP(), []int{7}
}

func (x *LoadDEKResponse) GetClearKey() []byte {
	if x != nil {
		return x.ClearKey
	}
	return nil
}

var File_apis_istio_v0_messages_proto protoreflect.FileDescriptor

var file_apis_istio_v0_messages_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x61, 0x70, 0x69, 0x73, 0x2f, 0x69, 0x73, 0x74, 0x69, 0x6f, 0x2f, 0x76, 0x30, 0x2f,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a,
	0x74, 0x68, 0x61, 0x6c, 0x65, 0x73, 0x63, 0x70, 0x6c, 0x2e, 0x69, 0x6f, 0x2e, 0x65, 0x6b, 0x6d,
	0x73, 0x2e, 0x69, 0x73, 0x74, 0x69, 0x6f, 0x2e, 0x76, 0x30, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2c, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x73, 0x77, 0x61, 0x67, 0x67, 0x65, 0x72, 0x2f,
	0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x2a, 0x0a, 0x0e, 0x56, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x77, 0x0a, 0x0f, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x12, 0x21, 0x0a, 0x0c, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d,
	0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65,
	0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e,
	0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x61,
	0x0a, 0x12, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x44, 0x45, 0x4b, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x12, 0x37, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x23, 0x2e, 0x74, 0x68, 0x61, 0x6c, 0x65, 0x73, 0x63,
	0x70, 0x6c, 0x2e, 0x69, 0x6f, 0x2e, 0x65, 0x6b, 0x6d, 0x73, 0x2e, 0x69, 0x73, 0x74, 0x69, 0x6f,
	0x2e, 0x76, 0x30, 0x2e, 0x4b, 0x65, 0x79, 0x4b, 0x69, 0x6e, 0x64, 0x52, 0x04, 0x6b, 0x69, 0x6e,
	0x64, 0x22, 0x43, 0x0a, 0x13, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x44, 0x45, 0x4b,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2c, 0x0a, 0x12, 0x65, 0x6e, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x62, 0x6c, 0x6f, 0x62, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x4b,
	0x65, 0x79, 0x42, 0x6c, 0x6f, 0x62, 0x22, 0x8f, 0x01, 0x0a, 0x12, 0x47, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x65, 0x53, 0x45, 0x4b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a,
	0x04, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x73, 0x69, 0x7a,
	0x65, 0x12, 0x37, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x23, 0x2e, 0x74, 0x68, 0x61, 0x6c, 0x65, 0x73, 0x63, 0x70, 0x6c, 0x2e, 0x69, 0x6f, 0x2e, 0x65,
	0x6b, 0x6d, 0x73, 0x2e, 0x69, 0x73, 0x74, 0x69, 0x6f, 0x2e, 0x76, 0x30, 0x2e, 0x4b, 0x65, 0x79,
	0x4b, 0x69, 0x6e, 0x64, 0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x2c, 0x0a, 0x12, 0x65, 0x6e,
	0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x62, 0x6c, 0x6f, 0x62,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
	0x64, 0x4b, 0x65, 0x79, 0x42, 0x6c, 0x6f, 0x62, 0x22, 0x43, 0x0a, 0x13, 0x47, 0x65, 0x6e, 0x65,
	0x72, 0x61, 0x74, 0x65, 0x53, 0x45, 0x4b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x2c, 0x0a, 0x12, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x6b, 0x65, 0x79,
	0x5f, 0x62, 0x6c, 0x6f, 0x62, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x65, 0x6e, 0x63,
	0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x4b, 0x65, 0x79, 0x42, 0x6c, 0x6f, 0x62, 0x22, 0x77, 0x0a,
	0x0e, 0x4c, 0x6f, 0x61, 0x64, 0x44, 0x45, 0x4b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x2c, 0x0a, 0x12, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x6b, 0x65, 0x79,
	0x5f, 0x62, 0x6c, 0x6f, 0x62, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x65, 0x6e, 0x63,
	0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x4b, 0x65, 0x79, 0x42, 0x6c, 0x6f, 0x62, 0x12, 0x37, 0x0a,
	0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x23, 0x2e, 0x74, 0x68,
	0x61, 0x6c, 0x65, 0x73, 0x63, 0x70, 0x6c, 0x2e, 0x69, 0x6f, 0x2e, 0x65, 0x6b, 0x6d, 0x73, 0x2e,
	0x69, 0x73, 0x74, 0x69, 0x6f, 0x2e, 0x76, 0x30, 0x2e, 0x4b, 0x65, 0x79, 0x4b, 0x69, 0x6e, 0x64,
	0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x22, 0x2e, 0x0a, 0x0f, 0x4c, 0x6f, 0x61, 0x64, 0x44, 0x45,
	0x4b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6c, 0x65,
	0x61, 0x72, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x63, 0x6c,
	0x65, 0x61, 0x72, 0x4b, 0x65, 0x79, 0x2a, 0x31, 0x0a, 0x07, 0x4b, 0x65, 0x79, 0x4b, 0x69, 0x6e,
	0x64, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x07,
	0x0a, 0x03, 0x41, 0x45, 0x53, 0x10, 0x01, 0x12, 0x07, 0x0a, 0x03, 0x52, 0x53, 0x41, 0x10, 0x02,
	0x12, 0x07, 0x0a, 0x03, 0x45, 0x43, 0x43, 0x10, 0x03, 0x42, 0x3c, 0x5a, 0x3a, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x68, 0x61, 0x6c, 0x65, 0x73, 0x63, 0x70,
	0x6c, 0x2d, 0x69, 0x6f, 0x2f, 0x6b, 0x38, 0x73, 0x2d, 0x6b, 0x6d, 0x73, 0x2d, 0x70, 0x6c, 0x75,
	0x67, 0x69, 0x6e, 0x2f, 0x61, 0x70, 0x69, 0x73, 0x2f, 0x69, 0x73, 0x74, 0x69, 0x6f, 0x2f, 0x76,
	0x30, 0x3b, 0x69, 0x73, 0x74, 0x69, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_apis_istio_v0_messages_proto_rawDescOnce sync.Once
	file_apis_istio_v0_messages_proto_rawDescData = file_apis_istio_v0_messages_proto_rawDesc
)

func file_apis_istio_v0_messages_proto_rawDescGZIP() []byte {
	file_apis_istio_v0_messages_proto_rawDescOnce.Do(func() {
		file_apis_istio_v0_messages_proto_rawDescData = protoimpl.X.CompressGZIP(file_apis_istio_v0_messages_proto_rawDescData)
	})
	return file_apis_istio_v0_messages_proto_rawDescData
}

var file_apis_istio_v0_messages_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_apis_istio_v0_messages_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_apis_istio_v0_messages_proto_goTypes = []interface{}{
	(KeyKind)(0),                // 0: thalescpl.io.ekms.istio.v0.KeyKind
	(*VersionRequest)(nil),      // 1: thalescpl.io.ekms.istio.v0.VersionRequest
	(*VersionResponse)(nil),     // 2: thalescpl.io.ekms.istio.v0.VersionResponse
	(*GenerateDEKRequest)(nil),  // 3: thalescpl.io.ekms.istio.v0.GenerateDEKRequest
	(*GenerateDEKResponse)(nil), // 4: thalescpl.io.ekms.istio.v0.GenerateDEKResponse
	(*GenerateSEKRequest)(nil),  // 5: thalescpl.io.ekms.istio.v0.GenerateSEKRequest
	(*GenerateSEKResponse)(nil), // 6: thalescpl.io.ekms.istio.v0.GenerateSEKResponse
	(*LoadDEKRequest)(nil),      // 7: thalescpl.io.ekms.istio.v0.LoadDEKRequest
	(*LoadDEKResponse)(nil),     // 8: thalescpl.io.ekms.istio.v0.LoadDEKResponse
}
var file_apis_istio_v0_messages_proto_depIdxs = []int32{
	0, // 0: thalescpl.io.ekms.istio.v0.GenerateDEKRequest.kind:type_name -> thalescpl.io.ekms.istio.v0.KeyKind
	0, // 1: thalescpl.io.ekms.istio.v0.GenerateSEKRequest.kind:type_name -> thalescpl.io.ekms.istio.v0.KeyKind
	0, // 2: thalescpl.io.ekms.istio.v0.LoadDEKRequest.kind:type_name -> thalescpl.io.ekms.istio.v0.KeyKind
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_apis_istio_v0_messages_proto_init() }
func file_apis_istio_v0_messages_proto_init() {
	if File_apis_istio_v0_messages_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_apis_istio_v0_messages_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VersionRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_istio_v0_messages_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VersionResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_istio_v0_messages_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateDEKRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_istio_v0_messages_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateDEKResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_istio_v0_messages_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateSEKRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_istio_v0_messages_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateSEKResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_istio_v0_messages_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LoadDEKRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_apis_istio_v0_messages_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LoadDEKResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_apis_istio_v0_messages_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_apis_istio_v0_messages_proto_goTypes,
		DependencyIndexes: file_apis_istio_v0_messages_proto_depIdxs,
		EnumInfos:         file_apis_istio_v0_messages_proto_enumTypes,
		MessageInfos:      file_apis_istio_v0_messages_proto_msgTypes,
	}.Build()
	File_apis_istio_v0_messages_proto = out.File
	file_apis_istio_v0_messages_proto_rawDesc = nil
	file_apis_istio_v0_messages_proto_goTypes = nil
	file_apis_istio_v0_messages_proto_depIdxs = nil
}
