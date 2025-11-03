package epicserver

import (
	"context"

	"github.com/tomskip123/EpicServer/auth"
)

type UserManagementHooks interface {
	Register(ctx context.Context, user auth.StatelessUser) (any, error)
}

type UserManagementWith[T any] struct {
	db     *EpicServerDatabaseWith[T]
	Hooks  UserManagementHooks
	Logger *Logger
}

type UserManagement = UserManagementWith[struct{}]

func NewUserManagement[T any](db *EpicServerDatabaseWith[T], logger *Logger) *UserManagementWith[T] {
	return &UserManagementWith[T]{
		db:     db,
		Logger: logger,
	}
}

func (usr *UserManagementWith[T]) RegisterUser(ctx context.Context, user *auth.StatelessUser) (any, error) {
	if usr.Hooks == nil {
		usr.Logger.Error.Println("please add UserManagementHooks")
	}

	return usr.Hooks.Register(ctx, *user)
}

func (usr *UserManagementWith[T]) IsEnabled() bool {
	return usr.db.Config.Features.EnableAuth && usr.db.Config.Features.EnableDB && usr.db.Config.Features.EnableUserMng
}
