// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: message.proto

package pb

import (
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

type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Conversation    *Conversation   `protobuf:"bytes,1,req,name=conversation" json:"conversation,omitempty"`
	FromUser        *string         `protobuf:"bytes,2,req,name=from_user,json=fromUser" json:"from_user,omitempty"`
	Content         *MessageContent `protobuf:"bytes,3,req,name=content" json:"content,omitempty"`
	MessageId       *int64          `protobuf:"varint,4,opt,name=message_id,json=messageId" json:"message_id,omitempty"`
	ServerTimestamp *int64          `protobuf:"varint,5,opt,name=server_timestamp,json=serverTimestamp" json:"server_timestamp,omitempty"`
	ToUser          *string         `protobuf:"bytes,6,opt,name=to_user,json=toUser" json:"to_user,omitempty"`
	To              []string        `protobuf:"bytes,7,rep,name=to" json:"to,omitempty"`
}

func (x *Message) Reset() {
	*x = Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_message_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_message_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_message_proto_rawDescGZIP(), []int{0}
}

func (x *Message) GetConversation() *Conversation {
	if x != nil {
		return x.Conversation
	}
	return nil
}

func (x *Message) GetFromUser() string {
	if x != nil && x.FromUser != nil {
		return *x.FromUser
	}
	return ""
}

func (x *Message) GetContent() *MessageContent {
	if x != nil {
		return x.Content
	}
	return nil
}

func (x *Message) GetMessageId() int64 {
	if x != nil && x.MessageId != nil {
		return *x.MessageId
	}
	return 0
}

func (x *Message) GetServerTimestamp() int64 {
	if x != nil && x.ServerTimestamp != nil {
		return *x.ServerTimestamp
	}
	return 0
}

func (x *Message) GetToUser() string {
	if x != nil && x.ToUser != nil {
		return *x.ToUser
	}
	return ""
}

func (x *Message) GetTo() []string {
	if x != nil {
		return x.To
	}
	return nil
}

type Conversation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type   *int32  `protobuf:"varint,1,req,name=type" json:"type,omitempty"`
	Target *string `protobuf:"bytes,2,req,name=target" json:"target,omitempty"`
	Line   *int32  `protobuf:"varint,3,req,name=line" json:"line,omitempty"`
}

func (x *Conversation) Reset() {
	*x = Conversation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_message_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Conversation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Conversation) ProtoMessage() {}

func (x *Conversation) ProtoReflect() protoreflect.Message {
	mi := &file_message_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Conversation.ProtoReflect.Descriptor instead.
func (*Conversation) Descriptor() ([]byte, []int) {
	return file_message_proto_rawDescGZIP(), []int{1}
}

func (x *Conversation) GetType() int32 {
	if x != nil && x.Type != nil {
		return *x.Type
	}
	return 0
}

func (x *Conversation) GetTarget() string {
	if x != nil && x.Target != nil {
		return *x.Target
	}
	return ""
}

func (x *Conversation) GetLine() int32 {
	if x != nil && x.Line != nil {
		return *x.Line
	}
	return 0
}

type MessageContent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type              *int32   `protobuf:"varint,1,req,name=type" json:"type,omitempty"`
	SearchableContent *string  `protobuf:"bytes,2,opt,name=searchable_content,json=searchableContent" json:"searchable_content,omitempty"`
	PushContent       *string  `protobuf:"bytes,3,opt,name=push_content,json=pushContent" json:"push_content,omitempty"`
	Content           *string  `protobuf:"bytes,4,opt,name=content" json:"content,omitempty"`
	Data              []byte   `protobuf:"bytes,5,opt,name=data" json:"data,omitempty"`
	MediaType         *int32   `protobuf:"varint,6,opt,name=mediaType" json:"mediaType,omitempty"`
	RemoteMediaUrl    *string  `protobuf:"bytes,7,opt,name=remoteMediaUrl" json:"remoteMediaUrl,omitempty"`
	PersistFlag       *int32   `protobuf:"varint,8,opt,name=persist_flag,json=persistFlag" json:"persist_flag,omitempty"`
	ExpireDuration    *int32   `protobuf:"varint,9,opt,name=expire_duration,json=expireDuration" json:"expire_duration,omitempty"`
	MentionedType     *int32   `protobuf:"varint,10,opt,name=mentioned_type,json=mentionedType" json:"mentioned_type,omitempty"`
	MentionedTarget   []string `protobuf:"bytes,11,rep,name=mentioned_target,json=mentionedTarget" json:"mentioned_target,omitempty"`
	Extra             *string  `protobuf:"bytes,12,opt,name=extra" json:"extra,omitempty"`
	PushData          *string  `protobuf:"bytes,13,opt,name=push_data,json=pushData" json:"push_data,omitempty"`
}

func (x *MessageContent) Reset() {
	*x = MessageContent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_message_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MessageContent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MessageContent) ProtoMessage() {}

func (x *MessageContent) ProtoReflect() protoreflect.Message {
	mi := &file_message_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MessageContent.ProtoReflect.Descriptor instead.
func (*MessageContent) Descriptor() ([]byte, []int) {
	return file_message_proto_rawDescGZIP(), []int{2}
}

func (x *MessageContent) GetType() int32 {
	if x != nil && x.Type != nil {
		return *x.Type
	}
	return 0
}

func (x *MessageContent) GetSearchableContent() string {
	if x != nil && x.SearchableContent != nil {
		return *x.SearchableContent
	}
	return ""
}

func (x *MessageContent) GetPushContent() string {
	if x != nil && x.PushContent != nil {
		return *x.PushContent
	}
	return ""
}

func (x *MessageContent) GetContent() string {
	if x != nil && x.Content != nil {
		return *x.Content
	}
	return ""
}

func (x *MessageContent) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *MessageContent) GetMediaType() int32 {
	if x != nil && x.MediaType != nil {
		return *x.MediaType
	}
	return 0
}

func (x *MessageContent) GetRemoteMediaUrl() string {
	if x != nil && x.RemoteMediaUrl != nil {
		return *x.RemoteMediaUrl
	}
	return ""
}

func (x *MessageContent) GetPersistFlag() int32 {
	if x != nil && x.PersistFlag != nil {
		return *x.PersistFlag
	}
	return 0
}

func (x *MessageContent) GetExpireDuration() int32 {
	if x != nil && x.ExpireDuration != nil {
		return *x.ExpireDuration
	}
	return 0
}

func (x *MessageContent) GetMentionedType() int32 {
	if x != nil && x.MentionedType != nil {
		return *x.MentionedType
	}
	return 0
}

func (x *MessageContent) GetMentionedTarget() []string {
	if x != nil {
		return x.MentionedTarget
	}
	return nil
}

func (x *MessageContent) GetExtra() string {
	if x != nil && x.Extra != nil {
		return *x.Extra
	}
	return ""
}

func (x *MessageContent) GetPushData() string {
	if x != nil && x.PushData != nil {
		return *x.PushData
	}
	return ""
}

var File_message_proto protoreflect.FileDescriptor

var file_message_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x02, 0x70, 0x62, 0x22, 0xfd, 0x01, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12,
	0x34, 0x0a, 0x0c, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x70, 0x62, 0x2e, 0x43, 0x6f, 0x6e, 0x76, 0x65,
	0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x66, 0x72, 0x6f, 0x6d, 0x5f, 0x75, 0x73,
	0x65, 0x72, 0x18, 0x02, 0x20, 0x02, 0x28, 0x09, 0x52, 0x08, 0x66, 0x72, 0x6f, 0x6d, 0x55, 0x73,
	0x65, 0x72, 0x12, 0x2c, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x03, 0x20,
	0x02, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x70, 0x62, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x12, 0x1d, 0x0a, 0x0a, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x49, 0x64, 0x12,
	0x29, 0x0a, 0x10, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0f, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x72, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x17, 0x0a, 0x07, 0x74, 0x6f,
	0x5f, 0x75, 0x73, 0x65, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x6f, 0x55,
	0x73, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x74, 0x6f, 0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x02, 0x74, 0x6f, 0x22, 0x4e, 0x0a, 0x0c, 0x43, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x02, 0x28,
	0x05, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65,
	0x74, 0x18, 0x02, 0x20, 0x02, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12,
	0x12, 0x0a, 0x04, 0x6c, 0x69, 0x6e, 0x65, 0x18, 0x03, 0x20, 0x02, 0x28, 0x05, 0x52, 0x04, 0x6c,
	0x69, 0x6e, 0x65, 0x22, 0xbb, 0x03, 0x0a, 0x0e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x43,
	0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01,
	0x20, 0x02, 0x28, 0x05, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x2d, 0x0a, 0x12, 0x73, 0x65,
	0x61, 0x72, 0x63, 0x68, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x61, 0x62,
	0x6c, 0x65, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x70, 0x75, 0x73,
	0x68, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x70, 0x75, 0x73, 0x68, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07,
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x1c, 0x0a, 0x09, 0x6d, 0x65,
	0x64, 0x69, 0x61, 0x54, 0x79, 0x70, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x6d,
	0x65, 0x64, 0x69, 0x61, 0x54, 0x79, 0x70, 0x65, 0x12, 0x26, 0x0a, 0x0e, 0x72, 0x65, 0x6d, 0x6f,
	0x74, 0x65, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x55, 0x72, 0x6c, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0e, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x55, 0x72, 0x6c,
	0x12, 0x21, 0x0a, 0x0c, 0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x5f, 0x66, 0x6c, 0x61, 0x67,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0b, 0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x46,
	0x6c, 0x61, 0x67, 0x12, 0x27, 0x0a, 0x0f, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x5f, 0x64, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x09, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0e, 0x65, 0x78,
	0x70, 0x69, 0x72, 0x65, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x25, 0x0a, 0x0e,
	0x6d, 0x65, 0x6e, 0x74, 0x69, 0x6f, 0x6e, 0x65, 0x64, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x0d, 0x6d, 0x65, 0x6e, 0x74, 0x69, 0x6f, 0x6e, 0x65, 0x64, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x29, 0x0a, 0x10, 0x6d, 0x65, 0x6e, 0x74, 0x69, 0x6f, 0x6e, 0x65, 0x64,
	0x5f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0f, 0x6d,
	0x65, 0x6e, 0x74, 0x69, 0x6f, 0x6e, 0x65, 0x64, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x14,
	0x0a, 0x05, 0x65, 0x78, 0x74, 0x72, 0x61, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65,
	0x78, 0x74, 0x72, 0x61, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x75, 0x73, 0x68, 0x5f, 0x64, 0x61, 0x74,
	0x61, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x73, 0x68, 0x44, 0x61, 0x74,
	0x61, 0x42, 0x05, 0x5a, 0x03, 0x2f, 0x70, 0x62,
}

var (
	file_message_proto_rawDescOnce sync.Once
	file_message_proto_rawDescData = file_message_proto_rawDesc
)

func file_message_proto_rawDescGZIP() []byte {
	file_message_proto_rawDescOnce.Do(func() {
		file_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_message_proto_rawDescData)
	})
	return file_message_proto_rawDescData
}

var file_message_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_message_proto_goTypes = []interface{}{
	(*Message)(nil),        // 0: pb.Message
	(*Conversation)(nil),   // 1: pb.Conversation
	(*MessageContent)(nil), // 2: pb.MessageContent
}
var file_message_proto_depIdxs = []int32{
	1, // 0: pb.Message.conversation:type_name -> pb.Conversation
	2, // 1: pb.Message.content:type_name -> pb.MessageContent
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_message_proto_init() }
func file_message_proto_init() {
	if File_message_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_message_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message); i {
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
		file_message_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Conversation); i {
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
		file_message_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MessageContent); i {
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
			RawDescriptor: file_message_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_message_proto_goTypes,
		DependencyIndexes: file_message_proto_depIdxs,
		MessageInfos:      file_message_proto_msgTypes,
	}.Build()
	File_message_proto = out.File
	file_message_proto_rawDesc = nil
	file_message_proto_goTypes = nil
	file_message_proto_depIdxs = nil
}
