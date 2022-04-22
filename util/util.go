package util

import (
	"encoding/json"
	"time"

	"github.com/jmoiron/sqlx/types"
)

func arrayContains(arr []string, str string) (int, bool) {
	for i, v := range arr {
		if v == str {
			return i, true
		}
	}
	return -1, false
}

func arrayDiff(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

type Int64Set map[int64]struct{}

func NewInt64Set(num ...int64) Int64Set {
	set := Int64Set{}
	for _, v := range num {
		set.Add(v)
	}
	return set
}

func (s Int64Set) Add(num int64) {
	s[num] = struct{}{}
}

func (s Int64Set) Values() []int64 {
	rtn := make([]int64, len(s))
	i := 0
	for k, _ := range s {
		rtn[i] = k
		i++
	}
	return rtn
}

type StringSet map[string]struct{}

func NewStringSet(str ...string) StringSet {
	set := StringSet{}
	for _, v := range str {
		set.Add(v)
	}
	return set
}

func (s StringSet) Add(str string) {
	s[str] = struct{}{}
}

func (s StringSet) AddAll(str ...string) {
	for _, v := range str {
		s.Add(v)
	}
}

func (s StringSet) Size() int {
	return len(s)
}

func (s StringSet) First() string {
	// TODO Store the order of the map
	for k, _ := range s {
		return k
	}
	return ""
}

func (s StringSet) Contains(str string) bool {
	_, ok := s[str]
	return ok
}

func (s StringSet) Values() []string {
	rtn := make([]string, s.Size())
	i := 0
	for k, _ := range s {
		rtn[i] = k
		i++
	}
	return rtn
}

func timeToJSONAttrs(format string, t *time.Time) (types.JSONText, types.JSONText) {
	norm := []int64{t.Unix()}
	orig := []string{t.In(time.UTC).Format(format)}

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	return types.JSONText(bNorm), types.JSONText(bOrig)
}

func nowTimeToJSONAttrs(format string) (types.JSONText, types.JSONText) {
	now := time.Now()

	norm := []int64{now.Unix()}
	orig := []string{now.In(time.UTC).Format(format)}

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	return types.JSONText(bNorm), types.JSONText(bOrig)
}

func emptyJSONArray() (types.JSONText, types.JSONText) {
	norm := make([]string, 0)
	orig := make([]string, 0)

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	return types.JSONText(bNorm), types.JSONText(bOrig)
}

func timesToJSONAttrs(format string, t []*time.Time) (types.JSONText, types.JSONText) {
	norm := make([]int64, len(t))
	orig := make([]string, len(t))

	for i, v := range t {
		norm[i] = v.Unix()
		orig[i] = v.In(time.UTC).Format(format)
	}

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	return types.JSONText(bNorm), types.JSONText(bOrig)
}

type SetString struct {
	set  map[string]struct{}
	list []string
}

func NewSetString() *SetString {
	return &SetString{
		set:  map[string]struct{}{},
		list: []string{},
	}
}

func (s *SetString) AddAll(str []string) {
	for _, v := range str {
		s.Add(v)
	}
}

func (s *SetString) Add(str string) {
	if _, ok := s.set[str]; !ok {
		s.set[str] = struct{}{}
		s.list = append(s.list, str)
	}
}

func (s *SetString) List() []string {
	return s.list
}
