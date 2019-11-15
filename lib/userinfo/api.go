package userinfo

// UserInfo is the interface that wraps the GetUserGroups method.
//
// GetUserGroups gets the groups that the user specified by username is a member
// of. If groupPrefix is not nil, only groups which have this prefix will be
// returned and the prefix will be stripped from these groups.
type UserInfo interface {
	GetUserGroups(username string, groupPrefix *string) ([]string, error)
}
