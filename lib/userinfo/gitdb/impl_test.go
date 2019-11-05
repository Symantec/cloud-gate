package gitdb

import (
	"testing"

	"github.com/Cloud-Foundations/Dominator/lib/log/testlogger"
)

func TestFlat(t *testing.T) {
	uinfo := UserInfo{logger: testlogger.New(t)}
	if err := uinfo.loadDatabase("testdata/flat"); err != nil {
		t.Fatal(err)
	}
	uinfo.testDB(t)
}

func TestNoFiles(t *testing.T) {
	uinfo := UserInfo{logger: testlogger.New(t)}
	if err := uinfo.loadDatabase("testdata"); err == nil {
		t.Fatal("error not returned for unpopulated directory tree")
	}
}

func TestLoop(t *testing.T) {
	uinfo := UserInfo{logger: testlogger.New(t)}
	if err := uinfo.loadDatabase("testdata/loop"); err != nil {
		t.Fatal(err)
	}
	for user, groups := range uinfo.groupsPerUser {
		if len(groups) != 3 {
			return
		}
		uinfo.logger.Printf("%s: %v\n", user, groups)
	}
	t.Fatal("loop detection failed: all users are members of all groups")
}

func TestTree(t *testing.T) {
	uinfo := UserInfo{logger: testlogger.New(t)}
	if err := uinfo.loadDatabase("testdata/tree"); err != nil {
		t.Fatal(err)
	}
	uinfo.testDB(t)
}

func (uinfo *UserInfo) testDB(t *testing.T) {
	if groups, ok := uinfo.groupsPerUser["userA"]; !ok {
		t.Fatal("no groups for userA")
	} else if _, ok := groups["project0"]; !ok {
		t.Fatal("userA not found in project0")
	} else if !uinfo.TestUserInGroup("userA", "project0") {
		t.Fatal("userA not found in project0 using TestUserInGroup")
	} else if _, ok := groups["team0"]; !ok {
		t.Fatal("userA not found in team0")
	} else if _, ok := groups["unpermitted0"]; ok {
		t.Fatal("userA found in unpermitted team")
	} else if uinfo.TestUserInGroup("userA", "unpermitted0") {
		t.Fatal("userA found in unpermitted0 using TestUserInGroup")
	} else if len(groups) != 2 {
		t.Fatalf("userA in %d groups, expected 2", len(groups))
	} else if g, err := uinfo.GetUserGroups("userA", nil); err != nil {
		t.Fatal(err)
	} else if len(g) != 2 {
		t.Fatalf("userA in %d groups using GetUserGroups, expected 2",
			len(groups))
	}
	if groups, ok := uinfo.groupsPerUser["userB"]; !ok {
		t.Fatal("no groups for userB")
	} else if _, ok := groups["project1"]; !ok {
		t.Fatal("userA not found in project1")
	} else if _, ok := groups["team1"]; !ok {
		t.Fatal("userA not found in team1")
	} else if len(groups) != 2 {
		t.Fatalf("userB in %d groups, expected 2", len(groups))
	}
}
