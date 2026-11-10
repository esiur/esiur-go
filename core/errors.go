// Package core holds what every Esiur layer shares: the errors that cross the wire.
package core

import (
	"errors"
	"fmt"
)

// ErrorType is the category of an Error; it selects the error reply that carries it.
type ErrorType uint8

const (
	Management ErrorType = 0
	Exception  ErrorType = 1
	Warning    ErrorType = 2
)

// ExceptionCode is an Esiur management error code (the order matches the .NET enum).
type ExceptionCode uint16

const (
	RuntimeException ExceptionCode = iota
	HostNotReachable
	AccessDenied
	UserOrTokenNotFound
	ChallengeFailed
	ResourceNotFound
	AttachDenied
	InvalidMethod
	InvokeDenied
	CreateDenied
	AddParentDenied
	AddChildDenied
	ViewAttributeDenied
	UpdateAttributeDenied
	StoreNotFound
	ParentNotFound
	ChildNotFound
	ResourceIsNotStore
	DeleteDenied
	DeleteFailed
	UpdateAttributeFailed
	GetAttributesFailed
	ClearAttributesFailed
	TypeDefNotFound
	RenameDenied
	ClassNotFound
	MethodNotFound
	PropertyNotFound
	SetPropertyDenied
	ReadOnlyProperty
	GeneralFailure
	AddToStoreFailed
	NotAttached
	AlreadyListened
	AlreadyUnsubscribed
	NotSubscribable
	ParseError
	Timeout
	NotSupported
	NotImplemented
	NotAllowed
	RateLimitExceeded
	ParserLimitExceeded
	AttachmentLimitExceeded
	AlreadyAttached
	ConnectionLimitExceeded
	CursorExpired
)

var codeNames = [...]string{
	"RuntimeException", "HostNotReachable", "AccessDenied", "UserOrTokenNotFound",
	"ChallengeFailed", "ResourceNotFound", "AttachDenied", "InvalidMethod", "InvokeDenied",
	"CreateDenied", "AddParentDenied", "AddChildDenied", "ViewAttributeDenied",
	"UpdateAttributeDenied", "StoreNotFound", "ParentNotFound", "ChildNotFound",
	"ResourceIsNotStore", "DeleteDenied", "DeleteFailed", "UpdateAttributeFailed",
	"GetAttributesFailed", "ClearAttributesFailed", "TypeDefNotFound", "RenameDenied",
	"ClassNotFound", "MethodNotFound", "PropertyNotFound", "SetPropertyDenied",
	"ReadOnlyProperty", "GeneralFailure", "AddToStoreFailed", "NotAttached", "AlreadyListened",
	"AlreadyUnsubscribed", "NotSubscribable", "ParseError", "Timeout", "NotSupported",
	"NotImplemented", "NotAllowed", "RateLimitExceeded", "ParserLimitExceeded",
	"AttachmentLimitExceeded", "AlreadyAttached", "ConnectionLimitExceeded", "CursorExpired",
}

func (c ExceptionCode) String() string {
	if int(c) < len(codeNames) {
		return codeNames[c]
	}
	return fmt.Sprintf("ExceptionCode(%d)", uint16(c))
}

// Error is an error reported by, or sent to, a peer: a category, a code and a message
// (esiur-ts AsyncException).
type Error struct {
	Type    ErrorType
	Code    ExceptionCode
	Message string
	// Cause is the local error this one was made from, if any.
	Cause error
}

// NewError builds an Error.
func NewError(t ErrorType, code ExceptionCode, message string) *Error {
	return &Error{Type: t, Code: code, Message: message}
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Code.String() + ": " + e.Message
	}
	return e.Code.String()
}

func (e *Error) Unwrap() error { return e.Cause }

// Is matches another *Error with the same code (and any *Error when the target code is the
// zero RuntimeException with an empty message is not special-cased).
func (e *Error) Is(target error) bool {
	var t *Error
	if errors.As(target, &t) {
		return t.Code == e.Code && t.Type == e.Type
	}
	return false
}

// FromError coerces any error: an *Error is returned as it is, anything else becomes an
// Exception with code RuntimeException.
func FromError(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Type: Exception, Code: RuntimeException, Message: err.Error(), Cause: err}
}

// Management builds a management error.
func ManagementError(code ExceptionCode, format string, args ...any) *Error {
	return &Error{Type: Management, Code: code, Message: fmt.Sprintf(format, args...)}
}
