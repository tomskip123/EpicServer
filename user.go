package epicserver

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

type User struct {
	EpicServerModel

	Name    string
	Email   string
	Picture string
}

type UserManagement struct {
	db *EpicServerDatabase
}

func NewUserManagement(db *EpicServerDatabase) *UserManagement {
	return &UserManagement{
		db: db,
	}
}

func (usr *UserManagement) RegisterUser(ctx context.Context, user *User) (any, error) {
	if usr.db.Client == nil {
		return nil, errors.New("please establish gorm client")
	}

	result, _ := gorm.G[User](usr.db.Client).Where("email = ?", user.Email).Take(ctx)
	if result.Email != "" {
		return nil, errors.New("User exists")
	}

	err := gorm.G[User](usr.db.Client).Create(ctx, user)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (usr *UserManagement) IsEnabled() bool {
	return usr.db.Config.Features.EnableAuth && usr.db.Config.Features.EnableDB && usr.db.Config.Features.EnableUserMng
}

func (usr *UserManagement) MigrateUserModel() error {
	return usr.db.Client.AutoMigrate(&User{})
}
