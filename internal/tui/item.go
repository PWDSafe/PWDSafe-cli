package tui

import "fmt"

// item is a single credential entry shown in the searchable list.
type item struct {
	credID    int
	name      string
	url       string
	username  string
	notes     string
	groupName string
	groupID   int
	hasTOTP   bool
}

func (i item) Title() string { return i.name }

func (i item) Description() string {
	return fmt.Sprintf("%s  ·  %s", i.username, i.groupName)
}

func (i item) FilterValue() string {
	return i.name + " " + i.username + " " + i.groupName
}
