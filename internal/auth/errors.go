package auth

import "errors"

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrAppNotInstalled    = errors.New("github app not installed")
	ErrGitLabNotConnected = errors.New("gitlab not connected")
)
