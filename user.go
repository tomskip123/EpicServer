package epicserver

import (
	"context"

	"github.com/tomskip123/EpicServer/auth"
)

type UserManagementHooks interface {
	Register(ctx context.Context, user auth.StatelessUser) (any, error)
}

type UserManagement struct {
	db     *EpicServerDatabase
	Hooks  UserManagementHooks
	Logger *Logger
}

func NewUserManagement(db *EpicServerDatabase, logger *Logger) *UserManagement {
	return &UserManagement{
		db:     db,
		Logger: logger,
	}
}

func (usr *UserManagement) RegisterUser(ctx context.Context, user *auth.StatelessUser) (any, error) {
	if usr.Hooks == nil {
		usr.Logger.Error.Println("please add UserManagementHooks")
	}

	return usr.Hooks.Register(ctx, *user)
}

func (usr *UserManagement) IsEnabled() bool {
	return usr.db.Config.Features.EnableAuth && usr.db.Config.Features.EnableDB && usr.db.Config.Features.EnableUserMng
}
