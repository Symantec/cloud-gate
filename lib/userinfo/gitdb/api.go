package gitdb

import (
	"sync"
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/log"
)

type UserInfo struct {
	logger        log.DebugLogger
	rwMutex       sync.RWMutex                   // Protect everything below.
	groupsPerUser map[string]map[string]struct{} // K: username, V: groups.
}

func New(repositoryURL, localRepositoryDir string,
	checkInterval time.Duration, logger log.DebugLogger) (
	*UserInfo, error) {
	return newDB(repositoryURL, localRepositoryDir, checkInterval, logger)
}

func (uinfo *UserInfo) GetUserGroups(username string, groupPrefix *string) (
	[]string, error) {
	return uinfo.getUserGroups(username, groupPrefix)
}

func (uinfo *UserInfo) TestUserInGroup(username, groupname string) bool {
	return uinfo.testUserInGroup(username, groupname)
}
