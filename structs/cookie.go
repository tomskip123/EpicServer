package structs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
)

type CookieHandler struct {
	SecureCookie *securecookie.SecureCookie
}

// NewCookieHandler creates a new CookieHandler
func NewCookieHandler() *CookieHandler {
	secureCookieHashKey := os.Getenv("SECURE_COOKIE_HASH_KEY")
	secureCookieBlockKey := os.Getenv("SECURE_COOKIE_BLOCK_KEY")

	hashKey, err := base64.StdEncoding.DecodeString(secureCookieHashKey)
	if err != nil {
		panic("Failed to decode hash key: " + err.Error())
	}

	blockKey, err := base64.StdEncoding.DecodeString(secureCookieBlockKey)
	if err != nil {
		panic("Failed to decode block key: " + err.Error())
	}

	return &CookieHandler{
		SecureCookie: securecookie.New(hashKey, blockKey),
	}
}

type CookieContents struct {
	Email      string
	UserId     string
	SessionId  string
	IsLoggedIn bool
	ExpiresOn  time.Time
}

func (cc *CookieContents) DeserialiseCookie(cookieString string) (*CookieContents, error) {
	err := json.Unmarshal([]byte(cookieString), cc)
	if err != nil {
		return nil, err
	}

	return cc, nil
}

func (ch *CookieHandler) SetCookieHandler(ctx *gin.Context, value *CookieContents, cookieName string, appConfig *AppConfig) error {
	expiry := time.Hour * 24 * 7
	value.ExpiresOn = time.Now().Add(expiry)

	// set cookie contents to json
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	if encoded, err := ch.SecureCookie.Encode(cookieName, jsonValue); err == nil {
		ctx.SetCookie(
			cookieName,
			encoded,
			int(expiry.Seconds()),
			"/",
			appConfig.CookieDomain,
			appConfig.CookieSecure,
			true,
		)

		return nil
	}

	return errors.New("error setting cookie")
}

func (ch *CookieHandler) ReadCookieHandler(ctx *gin.Context, cookieName string) (string, error) {
	cookie, err := ctx.Cookie(cookieName)
	if err == nil {
		var value []byte
		// fmt.Println("cookie: ", cookie)
		err = ch.SecureCookie.Decode(cookieName, cookie, &value)
		if err == nil {
			valueStr := string(value)
			return valueStr, nil
		}
	}

	return "", err
}
