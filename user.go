package epicserver

import (
	"errors"
	"reflect"
)

type User struct {
	EpicServerModel

	Name  string
	Email string
}

type UserManagement struct {
	db        *EpicServerDatabase
	userModel any
}

func NewUserManagement(db *EpicServerDatabase) *UserManagement {
	return &UserManagement{
		db:        db,
		userModel: &User{},
	}
}

// SetModel lets callers supply a pointer to their custom user struct that embeds UserModel.
func (m *UserManagement) SetModel(model any) error {
	if model == nil {
		return errors.New("model cannot be nil")
	}
	t := reflect.TypeOf(model)
	if t.Kind() != reflect.Ptr || t.Elem().Kind() != reflect.Struct {
		return errors.New("model must be a pointer to struct")
	}

	// Ensure it either embeds UserModel or at least has Name & Email fields.
	elem := t.Elem()
	hasName := false
	hasEmail := false
	embedsUserModel := false

	for i := 0; i < elem.NumField(); i++ {
		f := elem.Field(i)
		if f.Anonymous && f.Type == reflect.TypeOf(User{}) {
			embedsUserModel = true
			break
		}
		if f.Name == "Name" {
			hasName = true
		}
		if f.Name == "Email" {
			hasEmail = true
		}
	}

	if !embedsUserModel && !(hasName && hasEmail) {
		return errors.New("custom model must embed UserModel or define Name and Email fields")
	}

	m.userModel = model
	return nil
}

func (usr *UserManagement) RegisterUser() {

}

func (usr *UserManagement) MigrateUserModel() error {
	return usr.db.DirectClient.AutoMigrate(usr.userModel)
}
