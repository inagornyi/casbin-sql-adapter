package sqladapter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitAdapter(t *testing.T) {
	_, err := NewAdapter("mysql", "root", "root", "127.0.0.1:3306", "casbin", "casbin_rule")
	assert.Nil(t, err)
}
