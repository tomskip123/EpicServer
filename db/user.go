package db

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DeviceId = string

type UserModel struct {
	ID                        string                                         `bson:"_id,omitempty"`
	Name                      string                                         `bson:"name"`
	Email                     string                                         `bson:"email"`
	Provider                  string                                         `bson:"provider"`
	BrainDump                 string                                         `bson:"brainDump"`
	Features                  []string                                       `bson:"features"`
	NotificationSubscriptions map[DeviceId]UserNotificationSubscriptionModel `bson:"notificationSubscription"`
	Settings                  *SettingsModel                                 `bson:"settings"`
	AvatarImage               string                                         `bson:"avatarImage"`
}

type SettingsModel struct {
	RecieveNotifications                   bool `bson:"recieveNotifications"`
	RecieveDailyTodoBreakdownNotifications bool `bson:"recieveDailyTodoBreakdownNotifications"`
}

type NotificationSubscriptionModel struct {
	Endpoint string `bson:"endpoint"`
	Keys     struct {
		P256dh string `bson:"p256dh"`
		Auth   string `bson:"auth"`
	} `bson:"keys"`
}

// UserNotificationSubscriptionModel UserNotificationSubscriptionModel this will be unique to each browser, and can be filtered or removed each time we get a 401
type UserNotificationSubscriptionModel struct {
	DeviceId     DeviceId                      `bson:"deviceId"`
	UserAgent    string                        `bson:"userAgent"`
	Subscription NotificationSubscriptionModel `bson:"subscription"`
	Timezone     string                        `bson:"timezone"`
}

type User struct {
	Collection *mongo.Collection
}

func (u *User) CheckIndexes(ctx context.Context) {
	indexModels := []mongo.IndexModel{
		{Keys: bson.M{"email": 1}},
	}

	UpdateIndexes(
		ctx,
		u.Collection,
		indexModels,
	)
}

func (u *User) UpdateSettings(ctx context.Context, userId string, settings SettingsModel) error {
	user := &UserModel{}
	user.Settings = &settings

	objUserId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return err
	}

	// update one field
	_, err = u.Collection.UpdateOne(ctx, bson.M{"_id": objUserId}, bson.M{"$set": bson.M{"settings": user.Settings}})
	if err != nil {
		return err
	}
	return nil

}

func (u *User) FindOneByEmail(email string) (*UserModel, error) {
	user := &UserModel{}
	err := u.Collection.FindOne(context.TODO(), bson.M{"email": email}).Decode(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (u *User) FindOne(userId string) (*UserModel, error) {
	objID, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return nil, err
	}

	user := &UserModel{}
	err = u.Collection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (u *User) Create(email string, name string, image string) (*UserModel, error) {
	user := &UserModel{
		Name:        name,
		Email:       email,
		Provider:    "google",
		Features:    []string{},
		AvatarImage: image,
		Settings: &SettingsModel{
			RecieveNotifications: true,
		},
		NotificationSubscriptions: map[DeviceId]UserNotificationSubscriptionModel{},
	}

	insertOneRes, err := u.Collection.InsertOne(context.TODO(), user)
	if err != nil {
		return nil, err
	}

	user.ID = insertOneRes.InsertedID.(primitive.ObjectID).Hex()
	return user, nil
}

func (u *User) Find() {
	// Implement Find

}

func (u *User) UpdateQuickNotes(ctx *gin.Context, userId string, content string) error {
	objUserId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return err
	}

	// update one field
	_, err = u.Collection.UpdateOne(ctx, bson.M{"_id": objUserId}, bson.M{"$set": bson.M{"brainDump": content}})
	if err != nil {
		return err
	}
	return nil
}

func (u *User) AddNotificationSubscriptions(ctx context.Context, userId string, subscription UserNotificationSubscriptionModel) error {
	if len(subscription.DeviceId) <= 0 {
		return fmt.Errorf("subscription has no device id")
	}

	objUserId := StringToObjectID(userId)

	filter := bson.M{
		"_id": objUserId,
	}

	// Define the update to set the subscription in the object indexed by DeviceId
	update := bson.M{
		"$set": bson.M{
			"notificationSubscription." + subscription.DeviceId: subscription,
		},
	}

	// Perform the update
	_, err := u.Collection.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	if err != nil {
		return err
	}

	return nil
}

func (u *User) GetUserNotificationSubscription(ctx context.Context, userId string, subscription UserNotificationSubscriptionModel) (bool, error) {
	objUserId := StringToObjectID(userId)

	filter := bson.M{
		"_id":                               objUserId,
		"notificationSubscription.endpoint": subscription.Subscription.Endpoint,
	}

	var uNSub UserModel
	err := u.Collection.FindOne(ctx, filter).Decode(&uNSub)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (u *User) UpdateOne() {
}

func (u *User) DeleteOne() {
	// Implement DeleteOne
}

func (u *User) GetAll(ctx context.Context) ([]*UserModel, error) {
	cursor, err := u.Collection.Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}

	defer cursor.Close(ctx)

	var users []*UserModel
	if err = cursor.All(ctx, &users); err != nil {
		return nil, err
	}

	return users, nil
}
