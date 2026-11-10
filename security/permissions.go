package security

// ActionType is the kind of operation being asked about (same values as esiur-dotnet).
type ActionType uint8

const (
	ActionAttach ActionType = iota
	ActionDelete
	ActionExecute
	ActionGetProperty
	ActionSetProperty
	ActionCreateResource
	ActionUpdateAttributes
	ActionInquireAttributes
	ActionAddParent
	ActionRemoveParent
	ActionAddChild
	ActionRemoveChild
	ActionRename
	ActionReceiveEvent
	ActionViewTypeDef
	ActionDetach
	ActionSubscribe
	ActionUnsubscribe
	ActionPullStream
	ActionTerminateExecution
	ActionHaltExecution
	ActionResumeExecution
)

// Ruling is a permissions manager's vote.
type Ruling uint8

const (
	Denied   Ruling = 0
	Allowed  Ruling = 1
	DontCare Ruling = 2
)

// DefaultPermissions is the verdict when no manager voted: read-like and lifecycle actions are
// allowed, anything that changes or administers a resource is denied.
func DefaultPermissions(action ActionType) Ruling {
	switch action {
	case ActionGetProperty, ActionViewTypeDef, ActionReceiveEvent, ActionAttach, ActionExecute,
		ActionDetach, ActionSubscribe, ActionUnsubscribe, ActionPullStream,
		ActionTerminateExecution, ActionHaltExecution, ActionResumeExecution:
		return Allowed
	}
	return Denied
}

// PermissionsManager is asked about every operation a peer attempts. Any denial wins, an
// allowance counts only when nothing denied, and when nobody cared DefaultPermissions decides.
//
// resource is the hosted resource (nil for an operation on no particular resource, such as
// viewing a type), session the peer's session, member the *data.PropertyDefInfo,
// *data.FunctionDefInfo or *data.EventDefInfo concerned (nil for none) and inquirer the
// connection asking.
type PermissionsManager interface {
	Applicable(resource any, session *Session, action ActionType, member any, inquirer any) Ruling
}

// AllowAll allows every operation: for tests, and for servers that trust every peer.
type AllowAll struct{}

func (AllowAll) Applicable(any, *Session, ActionType, any, any) Ruling { return Allowed }

// PermissionsFunc adapts a function to a PermissionsManager.
type PermissionsFunc func(resource any, session *Session, action ActionType, member any, inquirer any) Ruling

func (f PermissionsFunc) Applicable(resource any, session *Session, action ActionType, member any, inquirer any) Ruling {
	return f(resource, session, action, member, inquirer)
}
