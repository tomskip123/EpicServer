package helpers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/cyberthy/server/db"
)

type PushNotificationData struct {
	Url string `json:"url"`
}

type PushNotificationPayload struct {
	Title string                `json:"title"`
	Body  string                `json:"body"`
	Type  string                `json:"type"`
	Data  *PushNotificationData `json:"data"`
}

// SendPushNotification sends a push notification to the given subscription
func sendWebPushNotification(subscription db.UserNotificationSubscriptionModel, payload PushNotificationPayload, subscriberEmail string) error {
	vapidPublicKey := "BGknowuNjU9MHfGnOIXWdyR6oESpMAUAtHCEQvrcfMOyXpqXbgZb5hyJu8Yv60zbhadOw1K_lOepN5TtSRa89S8"
	vapidPrivateKey := "qj7n0j7HyFU5c1FvxLfad6udPT_NdHN8rA9Nuhh52GA"

	// Create the subscription object
	sub := &webpush.Subscription{
		Endpoint: subscription.Subscription.Endpoint,
		Keys: webpush.Keys{
			P256dh: subscription.Subscription.Keys.P256dh,
			Auth:   subscription.Subscription.Keys.Auth,
		},
	}

	// Create the VAPID options
	vapidOptions := &webpush.Options{
		Topic:           "Todo",
		Urgency:         "high",
		Subscriber:      subscriberEmail,
		VAPIDPublicKey:  vapidPublicKey,
		VAPIDPrivateKey: vapidPrivateKey,
		TTL:             30,
	}

	message, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Send the push notification
	resp, err := webpush.SendNotification(message, sub, vapidOptions)
	if err != nil {
		return fmt.Errorf("failed to send push notification: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusCreated {
		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}

		// Print or log the response body
		fmt.Printf("Response body: %s\n", string(body))
		return fmt.Errorf("failed to send push notification, status code: %d", resp.StatusCode)
	}

	return nil
}

// SendNotification SendNotification we could have other types of push notifications here?
func SendNotification(user db.UserModel, subscription db.UserNotificationSubscriptionModel, payload PushNotificationPayload) {
	// Send the push notification
	err := sendWebPushNotification(subscription, payload, user.Email)
	if err != nil {
		log.Println("Failed to Send Notification")
		log.Printf("UserId: %v \n", user.ID)
		log.Printf("Subscription Endpoint: %v \n", subscription.Subscription.Endpoint)
		// TODO: do we add a mechanism to remove subscription automatically?
	}

	log.Println("Push notification sent successfully!")
}
