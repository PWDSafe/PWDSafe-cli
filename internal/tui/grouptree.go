package tui

import (
	"sort"

	"pwdsafe-cli/internal/api"
)

// groupNode is a single row in the flattened, depth-first ordered group tree
// shown in the sidebar. id == 0 is reserved for the synthetic "All
// credentials" entry.
type groupNode struct {
	id          int
	name        string
	depth       int
	count       int
	isAll       bool
	isSeparator bool

	// disabled marks a node as visible but non-selectable in a group-picker
	// tree (the credential's current group, or a group the user lacks
	// write/admin permission on).
	disabled bool
}

// buildGroupTree converts the flat, ParentID-linked group list plus the
// loaded credential items into a depth-first ordered slice of groupNode,
// with a synthetic "All credentials" entry prepended. Counts reflect
// credentials directly assigned to each group (no aggregation across
// subgroups).
func buildGroupTree(groups []api.Group, items []item) []groupNode {
	countByGroup := make(map[int]int, len(groups))
	for _, it := range items {
		countByGroup[it.groupID]++
	}

	children := make(map[int][]api.Group)

	var roots []api.Group

	for _, g := range groups {
		if g.ParentID == nil {
			roots = append(roots, g)
		} else {
			children[*g.ParentID] = append(children[*g.ParentID], g)
		}
	}

	byName := func(gs []api.Group) {
		sort.Slice(gs, func(i, j int) bool {
			if gs[i].IsPrimary != gs[j].IsPrimary {
				return gs[i].IsPrimary
			}

			return gs[i].Name < gs[j].Name
		})
	}

	byName(roots)
	for k := range children {
		byName(children[k])
	}

	nodes := []groupNode{{id: 0, name: "All credentials", depth: 0, count: len(items), isAll: true}}

	var walk func(g api.Group, depth int)
	walk = func(g api.Group, depth int) {
		name := g.Name
		if g.IsPrimary {
			name = "Private"
		}

		nodes = append(nodes, groupNode{
			id:    g.ID,
			name:  name,
			depth: depth,
			count: countByGroup[g.ID],
		})

		for _, child := range children[g.ID] {
			walk(child, depth+1)
		}
	}

	for _, g := range roots {
		walk(g, 0)

		if g.IsPrimary {
			nodes = append(nodes, groupNode{isSeparator: true})
		}
	}

	return nodes
}

// buildGroupPickerTree converts the flat, ParentID-linked group list into a
// depth-first ordered tree for the group-picker modal (no "All credentials"
// entry, no counts). Nodes are marked disabled if they are the credential's
// current group (currentGroupID) or the user lacks admin/write permission on
// them, so the hierarchy stays intact while non-selectable groups are shown
// dimmed rather than removed.
func buildGroupPickerTree(groups []api.Group, currentGroupID int) []groupNode {
	children := make(map[int][]api.Group)

	var roots []api.Group

	for _, g := range groups {
		if g.ParentID == nil {
			roots = append(roots, g)
		} else {
			children[*g.ParentID] = append(children[*g.ParentID], g)
		}
	}

	byName := func(gs []api.Group) {
		sort.Slice(gs, func(i, j int) bool {
			if gs[i].IsPrimary != gs[j].IsPrimary {
				return gs[i].IsPrimary
			}

			return gs[i].Name < gs[j].Name
		})
	}

	byName(roots)
	for k := range children {
		byName(children[k])
	}

	var nodes []groupNode

	var walk func(g api.Group, depth int)
	walk = func(g api.Group, depth int) {
		name := g.Name
		if g.IsPrimary {
			name = "Private"
		}

		nodes = append(nodes, groupNode{
			id:       g.ID,
			name:     name,
			depth:    depth,
			disabled: g.ID == currentGroupID || (g.Permission != "admin" && g.Permission != "write"),
		})

		for _, child := range children[g.ID] {
			walk(child, depth+1)
		}
	}

	for _, g := range roots {
		walk(g, 0)

		if g.IsPrimary {
			nodes = append(nodes, groupNode{isSeparator: true})
		}
	}

	return nodes
}
