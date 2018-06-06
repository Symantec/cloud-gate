package userinfo

type UserInfo interface {
	GetUserGroups(username string, groupPrefix *string) ([]string, error)
}
