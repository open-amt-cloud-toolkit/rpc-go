package smb

import (
	"github.com/stretchr/testify/assert"
	"os/user"
	"testing"
)

func TestService_ParseUrl(t *testing.T) {

	t.Run("expect happy path", func(t *testing.T) {
		svc := NewSambaService("smb://some.test.server/sharename/and/a/file/path.txt")
		err := svc.ParseUrl()
		assert.Nil(t, err)
		curUser, err := user.Current()
		assert.Nil(t, err)
		assert.Equal(t, "some.test.server", svc.Host)
		assert.Equal(t, "445", svc.Port)
		assert.Equal(t, "sharename", svc.ShareName)
		assert.Equal(t, "and/a/file/path.txt", svc.FilePath)
		assert.Equal(t, curUser.Username, svc.User)
		assert.Equal(t, "", svc.Password)
		assert.Equal(t, "", svc.Domain)
	})

	t.Run("expect happy path with username, and password", func(t *testing.T) {
		svc := NewSambaService("smb://test-user:test-pwd@some.test.server/sharename/and/a/file/path.txt")
		err := svc.ParseUrl()
		assert.Nil(t, err)
		assert.Equal(t, "some.test.server", svc.Host)
		assert.Equal(t, "445", svc.Port)
		assert.Equal(t, "sharename", svc.ShareName)
		assert.Equal(t, "and/a/file/path.txt", svc.FilePath)
		assert.Equal(t, "test-user", svc.User)
		assert.Equal(t, "test-pwd", svc.Password)
		assert.Equal(t, "", svc.Domain)
	})

	t.Run("expect happy path with domain, username, and no password", func(t *testing.T) {
		svc := NewSambaService("smb://test-domain;test-user@some.test.server/sharename/and/a/file/path.txt")
		err := svc.ParseUrl()
		assert.Nil(t, err)
		assert.Equal(t, "some.test.server", svc.Host)
		assert.Equal(t, "test-user", svc.User)
		assert.Equal(t, "", svc.Password)
		assert.Equal(t, "test-domain", svc.Domain)
	})
}
