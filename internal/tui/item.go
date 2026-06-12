package tui

import "fmt"

// item is a single credential entry shown in the searchable list.
type item struct {
	credID    int
	site      string
	username  string
	notes     string
	groupName string
	groupID   int
}

func (i item) Title() string { return i.site }

func (i item) Description() string {
	return fmt.Sprintf("%s  ·  %s", i.username, i.groupName)
}

func (i item) FilterValue() string {
	return i.site + " " + i.username + " " + i.groupName
}
